// import mongoose from "mongoose";

// const QuerySchema = new mongoose.Schema({
//   student: { type: mongoose.Schema.Types.ObjectId, ref: 'Student' },
//   message: String,
//   createdAt: { type: Date, default: Date.now },
// });

// const Query = mongoose.model('Query', QuerySchema);
// export default Query;

import mongoose from "mongoose";

const QuerySchema = new mongoose.Schema({
  name: {
    firstName: {
      type: String,
      required: true,
    },
    lastName: {
      type: String,
      required: true,
    },
  },
  contactNumber: {
    type: Number,
    required: true,
  },
  query: {
    type: String,
    enum: ["course content", "fee structure", "Other"],
  },
  status: {
    type: String,
    enum: ["pending", "resolved"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
});

const Query = mongoose.model("Query", QuerySchema);
export default Query;
