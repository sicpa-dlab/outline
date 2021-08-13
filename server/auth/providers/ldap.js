import accountProvisioner from "../../commands/accountProvisioner";
import { Strategy as LdapStrategy } from "passport-ldapauth";
import { signIn } from "../../utils/authentication";
import { AuthorizationError } from "../../errors";
import passport from "@outlinewiki/koa-passport";
import { User, Team } from "../../models";
import Router from "koa-router";

const router = new Router();
const providerName = "ldap";

const LDAP_TEAM_NAME = process.env.LDAP_TEAM_NAME;
const LDAP_PROVIDER_NAME = process.env.LDAP_PROVIDER_NAME;
const LDAP_URI = process.env.LDAP_URI;
const LDAP_BINDDN = process.env.LDAP_BINDDN;
const LDAP_SEARCH_BASE = process.env.LDAP_SEARCH_BASE;
const LDAP_SEARCH_FILTER = process.env.LDAP_SEARCH_FILTER;
const LDAP_PASSWORD = process.env.LDAP_PASSWORD;

export const config = {
  name: LDAP_PROVIDER_NAME,
  enabled: !!LDAP_URI,
  id: providerName,
};

if (LDAP_URI) {
  const strategy = new LdapStrategy(
    {
      server: {
        url: LDAP_URI,
        bindDN: LDAP_BINDDN,
        bindCredentials: LDAP_PASSWORD,
        searchBase: LDAP_SEARCH_BASE,
        searchFilter: LDAP_SEARCH_FILTER,
      },
      passReqToCallback: true,
    },
    async function (req, profile, done) {
      try {
        const domain = profile.mail.split("@")[1];
        const subdomain = domain.split(".")[0];

        const result = await accountProvisioner({
          ip: req.ip,
          team: {
            name: LDAP_TEAM_NAME,
            domain: domain,
            subdomain: subdomain,
          },
          user: {
            name: profile.displayName,
            email: profile.mail,
            //avatarUrl: profile.jpegPhoto,
          },
          authenticationProvider: {
            name: providerName,
            providerId: domain,
          },
          authentication: {
            providerId: profile.employeeID,
            accessToken: "",
            refreshToken: "",
            scopes: [],
          },
        });
        return done(null, result.user);
      } catch (err) {
        return done(err, null);
      }
    }
  );

  strategy.name = providerName;

  passport.use(strategy);

  passport.serializeUser(function (user, done) {
    done(null, user);
  });

  router.post(
    "ldap",
    passport.authenticate(providerName, {
      failureRedirect: "/?notice=auth-error",
    }),
    async (ctx) => {
      const userID = ctx.req.user?.id;

      if (!userID) {
        return ctx.redirect("/?notice=auth-error");
      }

      try {
        const user = await User.findByPk(userID, {
          include: [
            {
              model: Team,
              as: "team",
              required: true,
            },
          ],
        });

        if (!user) {
          return ctx.redirect("/?notice=auth-error");
        }

        if (user.isSuspended) {
          return ctx.redirect("/?notice=suspended");
        }

        await user.update({ lastActiveAt: new Date() });

        await signIn(ctx, user, user.team, providerName, false, false);
      } catch (err) {
        ctx.redirect(`/?notice=auth-error`);
      }
    }
  );
}

export default router;
