import mongoose from "mongoose";

const BranchSchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: { type: String, required: true },
  adminId: {
    type: mongoose.Types.ObjectId,
    ref:"User",
  }
  
});

const Branch = mongoose.model("Branch", BranchSchema);
export default Branch