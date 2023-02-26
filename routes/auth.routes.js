const { Router } = require('express')
const router = Router()
const User = require('../models/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { check, validationResult } = require('express-validator')
const config = require('config')

router.post('/register', [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Min 6 signes').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data by registration'
            })
        }
        const { email, password } = res.body
        const candidate = await User.findOne({ email })
        if (candidate) {
            return res.status(400).json({ message: 'User already exists' })
        }
        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword })
        await user.save()
        res.status(201).json({ message: 'User is created' })
    } catch (error) {
        res.status(500).json({ message: 'Smth is going wrong. Try again' })
    }
})

router.post('/login', [
    check('email', 'Enter correct email').normalizeEmail().isEmail(),
    check('password', 'Enter password').exists()
], async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Incorrect data by enter'
            })
        }
        const { email, password } = res.body
        const user = await User.findOne({ email })
        if (!user) {
            return res.status(400).json({ message: 'User is undefined' })
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(400).json({ message: 'Password is undefined' })
        }
        const token = jwt.sign({
            userId: user.id
        }, config.get('jwtSecret'),
        {expiresIn: '1h'})
        res.status(200).json({ token, userId: user.id })
    } catch (error) {
        res.status(500).json({ message: 'Smth is going wrong. Try again' })
    }
})

module.exports = router