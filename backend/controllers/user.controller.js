import { asyncHandler } from '../utils/asyncHandler.js'
import { ApiError } from '../utils/ApiError.js'
import { ApiResponse } from '../utils/ApiResponse.js'
import { User } from '../models/user.model.js'
import jwt from 'jsonwebtoken'


const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessTokens()
        const refreshToken = user.generateRefreshTokens()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }
    }
    catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    const { fullname, email, password, mobile_number, company_name } = req.body


    // validation - not empty
    if (!fullname || !email || !password) {
        throw new ApiError(400, 'All required fields must be filled')
    }
    // if (password !== confirm_password) {
    //     throw new ApiError(400, "Passwords do not match")
    // }

    // check if user already exists: username or email
    if (await User.exists({ email })) {
        throw new ApiError(409, 'Email already registered')
    }

    // create user object-  create entry in db
    const user = await User.create({
        fullname,
        email,
        password,
        mobile_number,
        company_name
    })

    // remove password and refresh token field from response
    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    // check for user creation
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering user")
    }

    // return response
    return res.status(201).json(
        new ApiResponse(201, createdUser, "user registered successfully")
    )
})

const loginUser = asyncHandler(async (req, res) => {
    // req body-> data
    // username and password
    // validate it and find the user
    // password check
    // generate access and refresh token 
    // send them in secure cookies

    const { email, password } = req.body
    console.log(`Login attempt: ${email}`)

    if (!email || !password) {
        throw new ApiError(400, "Email and password are required")
    }


    const user = await User.findOne({ email })

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Password is incorrect")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    // for generating cookie
    const options = {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        // expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    }
    return res
        .status(200)
        .cookie('accessToken', accessToken, options)
        .cookie('refreshToken', refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logged In successfully"
            )
        )
})

const logoutUser = asyncHandler(async (req, res) => {
    // Ensure req.user is available (e.g., from auth middleware)
    if (!req.user?._id) {
        throw new ApiError(401, "Unauthorized: No user context")
    }   
    // console.log(`Logout attempt: ${req.user.email}`)
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: { 
                accessToken: undefined,
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    );

    const options = {
        httpOnly: true,
        secure: true,
        sameSite: 'None'
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});


export {
    registerUser,
    loginUser,
    logoutUser
}