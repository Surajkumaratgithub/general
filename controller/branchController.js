import Branch from "../model/branchModel.js"

export const createBranch = async (req, res,next) => {
  try {
    const branch = await Branch.create(req.body);
    res.status(201).json({message:'Branch create successfuly',branch,success: true})
  } catch (error) {
    console.log('Error Occured while creating branch :', error.message);
    error.statusCode = 500
    next(error)
  }
}

export const getAllBranches = async (req,res,next) => {
    try {
    const branch = await Branch.find();
    res.status(200).json({message:'Branchs fetched successfuly',branch,success: true})
    } catch (error) {
    console.log('Error Occured while fetching branch :', error.message);
    error.statusCode = 500
    next(error)
    }
}


