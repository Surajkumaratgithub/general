import Joi from "joi";

export const validateTeacherData = (data) => {
  const schema = Joi.object({
    name: Joi.object({
      firstName: Joi.string().required(),
      lastName: Joi.string().required(),
    }).required(),

    email: Joi.string().email().required(),
    mobileNumber: Joi.string()
      .pattern(/^[0-9]{10,14}$/)
      .required(),
    password: Joi.string().min(6),
    alternativeNumber: Joi.string()
      .pattern(/^[0-9]{10,14}$/)
      .optional(),

    address: Joi.object({
      city: Joi.string().required(),
      country: Joi.string().required(),
      zipCode: Joi.string().required(),
    }).required(),

    dob: Joi.date().less("now").required().messages({
      "date.less": "Date of birth must be in the past.",
    }),

    maritalStatus: Joi.string()
      .valid("Single", "Married", "Divorced")
      .required(),
    religion: Joi.string()
      .valid("Hindu", "Muslim", "Christian", "Sikh", "Other")
      .optional(),
    citizenship: Joi.string().required(),
    gender: Joi.string().valid("Male", "Female", "Other").required(),

    dutyType: Joi.string().valid("Full Time", "Part Time").required(),
    joiningDate: Joi.date().optional(),
    payFrequency: Joi.string()
      .valid("Weekly", "Biweekly", "Monthly", "Annual")
      .required(),
    salary: Joi.number().min(0).required(),
    payFrequencyText: Joi.string().optional(),
    hourlyRate: Joi.number().min(0).optional(),

    bankDetails: Joi.object({
      bankName: Joi.string().required(),
      branchName: Joi.string().required(),
      accountNumber: Joi.string().required(),
      accountHolderName: Joi.string().required(),
      accountHolderType: Joi.string()
        .valid("Saving", "Salary", "Current")
        .required(),
      ifscCode: Joi.string().required(),
    }).required(),

    teachingMode: Joi.string().valid("online", "offline").default("online"),
    status: Joi.string().valid("Active", "Resigned", "Terminated").optional(),
  });

  return schema.validate(data, { abortEarly: false });
};
