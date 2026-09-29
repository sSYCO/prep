"use node";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

type AuthResult =
  | { ok: true; token: string; name: string }
  | { ok: false; message: string };

const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const hash = (password: string, salt: string) => scryptSync(password, salt, 64).toString("hex");

export const signup = action({
  args: { name: v.string(), email: v.string(), password: v.string() },
  handler: async (ctx, args): Promise<AuthResult> => {
    const name = args.name.trim();
    const email = args.email.trim().toLowerCase();
    if (name.length < 2 || !emailRe.test(email) || args.password.length < 8 || !/\d/.test(args.password)) {
      return { ok: false, message: "Please check your details and try again." };
    }
    const salt = randomBytes(16).toString("hex");
    const userId = await ctx.runMutation(internal.users.create, {
      name, email, passwordHash: hash(args.password, salt), salt,
    });
    if (!userId) return { ok: false, message: "This email is already registered. Try logging in." };
    const token = randomBytes(32).toString("hex");
    await ctx.runMutation(internal.users.createSession, { userId, token });
    return { ok: true, token, name };
  },
});

export const login = action({
  args: { email: v.string(), password: v.string() },
  handler: async (ctx, args): Promise<AuthResult> => {
    const bad: AuthResult = { ok: false, message: "Email or password is incorrect." };
    const email = args.email.trim().toLowerCase();
    const user = await ctx.runQuery(internal.users.getByEmail, { email });
    if (!user) return bad;
    const a = Buffer.from(hash(args.password, user.salt), "hex");
    const b = Buffer.from(user.passwordHash, "hex");
    if (a.length !== b.length || !timingSafeEqual(a, b)) return bad;
    const token = randomBytes(32).toString("hex");
    await ctx.runMutation(internal.users.createSession, { userId: user._id, token });
    return { ok: true, token, name: user.name };
  },
});