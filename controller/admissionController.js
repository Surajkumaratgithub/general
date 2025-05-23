import Admission from "../model/admissionModel.js";


// Create new admission
export const createAdmission = async (req, res) => {
  try {
    const { studentId, courseId, mode, branch, admissionDate, paymentStatus } =
      req.body;

    if (!studentId || !courseId || !mode || !branch) {
      return res.status(400).json({ message: "Required fields missing" });
    }

    const newAdmission = new Admission({
      studentId,
      courseId,
      mode,
      branch,
      admissionDate,
      paymentStatus,
    });

    await newAdmission.save();
    res
      .status(201)
      .json({ message: "Admission created successfully", data: newAdmission });
  } catch (error) {
    console.error("Error creating admission:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Get all admissions
export const getAllAdmissions = async (req, res) => {
  try {
    const admissions = await Admission.find()
      .populate("studentId", "name email") // optional
      // .populate("courseId", "courseName details") // optional
      .sort({ admissionDate: -1 });
      console.log("admission is",admissions);

    res.status(200).json(admissions);
  } catch (error) {
    console.error("Error fetching admissions:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Get single admission
export const getAdmissionById = async (req, res) => {
  try {
    const { id } = req.params;

    const admission = await Admission.findById(id)
      .populate("studentId", "name email")
      // .populate("courseId", "title");

    if (!admission) {
      return res.status(404).json({ message: "Admission not found" });
    }

    res.status(200).json(admission);
  } catch (error) {
    console.error("Error fetching admission:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Delete admission
export const deleteAdmission = async (req, res) => {
  try {
    const { id } = req.params;

    const deleted = await Admission.findByIdAndDelete(id);

    if (!deleted) {
      return res.status(404).json({ message: "Admission not found" });
    }

    res.status(200).json({ message: "Admission deleted successfully" });
  } catch (error) {
    console.error("Error deleting admission:", error);
    res.status(500).json({ message: "Server error" });
  }
};
