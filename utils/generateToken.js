import jwt from "jsonwebtoken";

export const createToken = (user, expiresIn = "7d") => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role || "student" },
    process.env.JWT_SECRET,
    {
      expiresIn,
    }
  );
};
