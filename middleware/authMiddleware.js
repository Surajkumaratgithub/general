import jwt from "jsonwebtoken";

import dotenv from "dotenv";

dotenv.config();

export const isAuth = async (req,res,next) => {
 try {
   const token = req.headers.authorization?.split(" ")[1];
     if (!token) {
       return res
         .status(401)
         .json({ error: "Access denied. No token provided." });
     }
 
   const decoded = jwt.verify(token, process.env.JWT_SECRET);
   if (decoded.exp * 1000 < Date.now()) {
       res.clearCookie('msToken'); 
    return res.status(401).json({ message: 'Access token has expired' });
   }
   req.user = decoded
 } catch (error) {
  next(error)
 }
}

export const accessToRole = (role=[]) =>{
 return async (req, res, next) => { 
   if (!role.includes(req.user.role)) {
    return res.status(403).json({
        error: `Access denied ,Only user with ${role} role is allowed`,
      });
   }
   next()
}}

// export const isStudent = async (req, res, next) => {
//   try {
//     const token = req.headers.authorization?.split(" ")[1];
//     if (!token) {
//       return res
//         .status(401)
//         .json({ error: "Access denied. No token provided." });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     // Find the student by the decoded ID
//     const student = await Student.findById(decoded.userId).select("-password");
//     if (!student) {
//       return res
//         .status(401)
//         .json({ error: "Invalid token or user not found." });
//     }

//     // Attach student to the request
//     req.student = student;
//     next(); // forward the request
//   } catch (err) {
//     console.error("Auth error:", err);
//     return res.status(401).json({ error: "Invalid or expired token." });
//   }
// };
//     // Attach student to the request
//     req.student = student;
//     next(); // forward the request
//   } catch (err) {
//     console.error("Auth error:", err);
//     return res.status(401).json({ error: "Invalid or expired token." });
//   }
// };

// export const isteacher = async (req, res, next) => {
//   try {
//     const token = req.headers.authorization?.split(" ")[1];
//     if (!token) {
//       return res
//         .status(401)
//         .json({ error: "Access denied. No token provided." });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     if (decoded.role !== "teacher") {
//       return res.status(403).json({ error: "Access denied. Not a teacher." });
//     }
//     if (decoded.role !== "teacher") {
//       return res.status(403).json({ error: "Access denied. Not a teacher." });
//     }

//     const teacher = await Teacher.findOne({
//       user: decoded.id,
//     });
//     if (!teacher) {
//       return res
//         .status(401)
//         .json({ error: "Invalid token or teacher not found." });
//     }
//     const teacher = await Teacher.findOne({
//       user: decoded.id,
//     });
//     if (!teacher) {
//       return res
//         .status(401)
//         .json({ error: "Invalid token or teacher not found." });
//     }

//     req.teacherId = teacher.id;
//     next();
//   } catch (err) {
//     console.error("Auth error:", err);
//     return res.status(401).json({ error: "Invalid or expired token." });
//   }
// };

// export const isSuperAdmin = async (req, res, next) => {
//   try {
//     const token = req.headers.authorization?.split(" ")[1];
//     if (!token) {
//       return res
//         .status(401)
//         .json({ error: "Access denied. No token provided." });
//     }

//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     if (decoded.role !== "superadmin") {
//       res.status(403).json({
//         error: "Can't proceed with the proccess,Only super admin is allowed",
//       });
//       return;
//     }
//     if (decoded.role !== "superadmin") {
//       res.status(403).json({
//         error: "Can't proceed with the proccess,Only super admin is allowed",
//       });
//       return;
//     }

//     // Find the student by the decoded ID
//     if (!decoded) {
//       return res
//         .status(401)
//         .json({ error: "Invalid token or user not found." });
//     }
//     // Find the student by the decoded ID
//     if (!decoded) {
//       return res
//         .status(401)
//         .json({ error: "Invalid token or user not found." });
//     }

//     // Attach student to the request
//     req.superAdmin = decoded.payload;
//     next(); // forward the request
//   } catch (err) {
//     console.error("Auth error:", err);
//     return res.status(401).json({ error: "Invalid or expired token." });
//   }
// };
//     // Attach student to the request
//     req.superAdmin = decoded.payload;
//     next(); // forward the request
//   } catch (err) {
//     console.error("Auth error:", err);
//     return res.status(401).json({ error: "Invalid or expired token." });
//   }
// };
