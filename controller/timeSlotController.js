import DemoTimeSlot from "../model/demoTimeSlots.js";

export const addTeacherTimeSlots = async (req, res) => {
  try {
    const { courseId, teacherId, date, slots } = req.body;

    if (!courseId || !teacherId || !date || !Array.isArray(slots) || slots.length === 0) {
      return res.status(400).json({ error: "courseId, teacherId, date, and slots are required." });
    }

    const dayStart = new Date(date);
    dayStart.setHours(0, 0, 0, 0);

    const dayEnd = new Date(date);
    dayEnd.setHours(23, 59, 59, 999);

    // Find existing slots on the same date for this teacher
    const existingSlotDoc = await DemoTimeSlot.findOne({
      teacherId,
      date: { $gte: dayStart, $lte: dayEnd },
    });

    const newSlots = slots.map(slot => ({
      start: new Date(slot.start),
      end: new Date(slot.end),
    }));

    // Conflict check
    if (existingSlotDoc) {
      for (const newSlot of newSlots) {
        for (const existing of existingSlotDoc.slots) {
          const existStart = new Date(existing.start);
          const existEnd = new Date(existing.end);
          const isOverlap =
            (newSlot.start >= existStart && newSlot.start < existEnd) ||
            (newSlot.end > existStart && newSlot.end <= existEnd) ||
            (newSlot.start <= existStart && newSlot.end >= existEnd);

          if (isOverlap) {
            return res.status(400).json({
              error: `Time conflict on ${date} between ${newSlot.start.toLocaleTimeString()} - ${newSlot.end.toLocaleTimeString()}`,
            });
          }
        }
      }


      existingSlotDoc.slots.push(...newSlots);
      const updated = await existingSlotDoc.save();
      return res.status(200).json({ message: "Slots added to existing date", data: updated });
    }

    const newSlotDoc = new DemoTimeSlot({
      courseId,
      teacherId,
      date: new Date(date),
      slots: newSlots,
    });
    const saved = await newSlotDoc.save();
    res.status(201).json({ message: "Time slots created successfully", data: saved });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


export const getAvailableSlots = async (req, res) => {
  try {
    const { courseId, teacherId, date } = req.query;

    const filters = {};
    if (courseId) filters.courseId = courseId;
    if (teacherId) filters.teacherId = teacherId;
    if (date) {
      const startOfDay = new Date(date);
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date(date);
      endOfDay.setHours(23, 59, 59, 999);
      filters.date = { $gte: startOfDay, $lte: endOfDay };
    }

    const slots = await DemoTimeSlot.find(filters).sort({ date: 1 });
    res.status(200).json({ message: "Slots fetched successfully", success: true, slots });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
