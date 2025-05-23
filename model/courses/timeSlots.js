import mongoose from "mongoose";

const TimeSlotsSchema = mongoose.Schema({
    courseId: {
        type: mongoose.Schema.Types.ObjectId,
        require: true,
        
    },
    teacherId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Teacher",
    },  
    date: {
        type: mongoose.Schema.Types.Date,
        require:true
    },
    startDate: { type: Date },
    endDate: { type: Date },
})


const TimeSlots = mongoose.model("TimeSlots", TimeSlotsSchema);
export default TimeSlots;