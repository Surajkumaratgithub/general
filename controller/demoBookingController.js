import DemoBooking from "../model/demoBookingSchema.js";

export const bookADemo = async (req, res, next) => {
  const { studentId, teacherId, courseId, date, slot } = req.body;

  if (!studentId || !teacherId || !courseId || !date || !slot?.startTime || !slot?.endTime) {
    return res.status(400).json({ message: "All fields are required including slot timings." });
  }

  try {
    const bookingDate = new Date(date);
    const startTime = new Date(slot.startTime);
    const endTime = new Date(slot.endTime);

    if (endTime <= startTime) {
      return res.status(400).json({ message: "End time must be after start time." });
    }

    // Check if already booked for same course and time
    const alreadyBooked = await DemoBooking.findOne({
      studentId,
      courseId,
      date: bookingDate,
      "slot.startTime": startTime,
      "slot.endTime": endTime,
    });

    if (alreadyBooked) {
      return res.status(400).json({ message: "You have already booked this slot.", data: alreadyBooked });
    }

    const booking = await DemoBooking.create({
      studentId,
      teacherId,
      courseId,
      date: bookingDate,
      slot: { startTime, endTime },
      status: "booked"
    });

    res.status(201).json({ message: "Slot booked successfully", success: true, data: booking });

  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
};


export const getAllDemoBookings = async (req, res, next) => {
    try {
        const bookings = await DemoBooking.find();
        res.status(200).json({message:"Successfully fetched all bookings",bookings})
    } catch (error) {
        error.statusCode = 500;
        next(error)
    }
    
}
export const getBookingByFilters = async (req, res, next) => {
  const { courseId, teacherId, date, startTime, endTime } = req.query;

  try {
    const filter = {};


    if (courseId) filter.courseId = courseId.trim();   // ✅ trim whitespace
    if (teacherId) filter.teacherId = teacherId.trim(); // ✅ trim whitespace
    if (date) filter.date = new Date(date);
    if (startTime && endTime) {
      filter["slot.startTime"] = { $gte: new Date(startTime) };
      filter["slot.endTime"] = { $lte: new Date(endTime) };
    }

console.log(filter)

    const bookings = await DemoBooking.find(filter).populate('studentId');

    res.status(200).json({
      message: "Filtered bookings fetched successfully",
      count: bookings.length,
      bookings,
    });
  } catch (error) {
    error.statusCode = 500;
    next(error);
  }
};



export const getDemoBookingById = async (req, res, next) => {
    const {id}=req.params
    try {
        const booking = await DemoBooking.findById(id);
        res.status(200).json({message:"Successfully fetched bookings by id",booking})
    } catch (error) {
         error.statusCode = 500;
    next(error)
    }
    
}

export const getDemoBookingByTeacherId = async (req, res, next) => {
    const {teacherId}=req.params
    try {
        const bookings = await DemoBooking.find({teacherId});
        res.status(200).json({message:"Successfully fetched bookings by teacherId",bookings})
    } catch (error) {
         error.statusCode = 500;
    next(error)
    }
    
}



export const getDemoBookingByCouseId = async (req, res, next) => {
    const {courseId}=req.params
    try {
        const bookings = await DemoBooking.find({courseId});
        res.status(200).json({message:"Successfully fetched bookings by courseId",bookings})
    } catch (error) {
         error.statusCode = 500;
    next(error)
    }
    
}