
export const microsoftLogin = async (req,res,next) => {
    try {
        const microsoft = req.microsoft
        res.status(200).cookie("msToken",microsoft,{httpOnly:true}).json({msToken:microsoft})
    } catch (error) {
        error.statusCode = 500
        next(error)
    }
}