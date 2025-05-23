import Joi from "joi";

export const validateTeacherApplication = (data) => {
  const schema = Joi.object({
    // Personal Details
    name: Joi.object({
      firstName: Joi.string().required().trim().messages({
        "string.empty": "First name is required",
      }),
      lastName: Joi.string().required().trim().messages({
        "string.empty": "Last name is required",
      }),
    }).required(),

    email: Joi.string().required().email().normalize().messages({
      "string.empty": "Email is required",
      "string.email": "Invalid email address",
    }),

    mobileNumber: Joi.string()
      .required()
      .trim()
      .pattern(/^[0-9]{10,14}$/)
      .messages({
        "string.empty": "Mobile number is required",
        "string.pattern.base": "Invalid mobile number",
      }),

    // Address
    address: Joi.object({
      addressLine: Joi.string().required().trim().messages({
        "string.empty": "Address line is required",
      }),
      city: Joi.string().required().trim().messages({
        "string.empty": "City is required",
      }),
      state: Joi.string().required().trim().messages({
        "string.empty": "State is required",
      }),
      country: Joi.string().required().trim().messages({
        "string.empty": "Country is required",
      }),
    }).required(),

    // Description
    description: Joi.string().required().trim().messages({
      "string.empty": "Description is required",
    }),

    // Experience
    experience: Joi.number().integer().min(0).required().messages({
      "number.base": "Experience must be a number",
      "number.min": "Experience must be a non-negative integer",
    }),

    // Teaching Mode
    teachingMode: Joi.string().valid("online", "offline").optional().messages({
      "any.only": 'Teaching mode must be either "online" or "offline"',
    }),

    // Skill
    skill: Joi.string().required().messages({
      "string.base": "Skill should be a string",
      "string.empty": "Skill is required",
    }),

    // Optional: languages
    languages: Joi.alternatives()
      .try(Joi.array().items(Joi.string().trim()), Joi.string())
      .optional(),
  });

  return schema.validate(data, { abortEarly: false });
};
