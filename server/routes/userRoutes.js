const { Router } = require("express");

const {
  registerUser,
  loginUser,
  getUser,
  changeAvatar,
  editUser,
  getAuthors,
} = require("../controllers/userControllers");

const authMiddleware = require("../middleware/authMiddleware");

const router = Router();

// router.get("/", (req, res, next) => {
//   res.json("this is the user route");
// });

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/:id", getUser);
router.get("/", getAuthors);
router.post("/change-avatar", authMiddleware, changeAvatar);
router.patch("/edit-user", authMiddleware, editUser);

module.exports = router;
