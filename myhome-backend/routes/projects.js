const express = require("express");
const router = express.Router();
const Project = require("../models/Project");
const authenticateToken = require("../middleware/authMiddleware");

router.post("/save", authenticateToken, async (req, res) => {
  const { name, data } = req.body;
  const userId = req.user.userId;

  try {
    const updatedProject = await Project.findOneAndUpdate(
      { name, userId },
      { name, userId, data },
      { upsert: true, new: true } 
    );

    res.status(200).json({
      message: "Project saved or updated successfully",
      projectId: updatedProject._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


router.get("/:userId", authenticateToken, async (req, res) => {
  try {
    if (req.user.userId !== req.params.userId) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const projects = await Project.find({ userId: req.params.userId });
    res.json(projects);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

router.delete("/:id", authenticateToken, async (req, res) => {
  const projectId = req.params.id;

  try {
    const deleted = await Project.findByIdAndDelete(projectId);
    if (!deleted) return res.status(404).json({ message: "Project not found" });

    res.status(200).json({ message: "Project deleted" });
  } catch (err) {
    console.error("Delete project error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


module.exports = router;
