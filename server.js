require("dotenv").config();

const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt")
const JWT_SECRET = process.env.JWT_SECRET || "Shub9GSBPR";
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 3030;

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

main().catch(err => console.error("MongoDB connection error:", err));
async function main() {
    await mongoose.connect(MONGO_URI);
    console.log("✅ Connected to MongoDB Atlas (shubdb)");
}


const { Schema, Types } = mongoose;

const userSchema = new Schema(
    {
        username: { type: String, required: true, unique: true },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        role: { type: String, enum: ["user", "admin"], default: "user" },
        savedPosts: [{ type: Types.ObjectId, ref: "Post" }],
    },
    { timestamps: true }
);

const commentSchema = new Schema(
    {
        author: { type: Types.ObjectId, ref: "User", required: false },
        anonymous: { type: Boolean, default: false },
        content: { type: String, required: true },
    },
    { timestamps: true }
);

const postSchema = new Schema(
    {
        author: { type: Types.ObjectId, ref: "User", required: false },
        anonymous: { type: Boolean, default: false },
        title: { type: String, required: true },
        content: { type: String, required: true },
        tags: [{ type: String }],
        upvoters: [{ type: Types.ObjectId, ref: "User" }],
        downvoters: [{ type: Types.ObjectId, ref: "User" }],
        comments: [commentSchema],
    },
    { timestamps: true }
);

const roadmapSchema = new Schema(
    {
        title: { type: String, required: true },
        link: { type: String, required: true },
        image: { type: String, required: true },
        content: { type: String, required: true },
    },
    { timestamps: true }
);

const repoSchema = new Schema(
    {
        title: { type: String, required: true },
        link: { type: String, required: true },
        image: { type: String, required: true },
        content: { type: String, required: true },
    },
    { timestamps: true }
);

const modLogSchema = new Schema(
    {
        action: { type: String, enum: ["delete_post", "delete_comment", "delete_roadmap", "delete_repo"], required: true },
        targetType: { type: String, required: true },
        targetId: { type: String, required: true },
        by: { type: Types.ObjectId, ref: "User", required: true },
        reason: { type: String, required: true },
    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);
const Roadmap = mongoose.model("Roadmap", roadmapSchema);
const Repo = mongoose.model("Repo", repoSchema);
const ModLog = mongoose.model("ModLog", modLogSchema);

function requireAuth(req, res, next) {
    try {
        const auth = req.headers.authorization || "";
        const token = auth.startsWith("Bearer ") ? auth.split(" ")[1] : null;
        if (!token) return res.status(401).json({ message: "Token missing" });
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(403).json({ message: "Invalid/expired token" });
    }
}

function optionalAuth(req, res, next) {
    try {
        const auth = req.headers.authorization || "";
        if (auth.startsWith("Bearer ")) {
            const token = auth.split(" ")[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        }
    } catch (_) { }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ message: "Admin only" });
    }
    next();
}

app.post("/register", async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ message: "username, email, password are required" });
        }

        const exists = await User.findOne({ $or: [{ username }, { email }] });
        if (exists) return res.status(400).json({ message: "User already exists" });

        const hash = await bcrypt.hash(password, 10);
        const user = await User.create({ username, email, password: hash, role: role === "admin" ? "admin" : "user" });
        res.json({
            message: "User registered successfully",
            user: { id: user._id, username: user.username, email: user.email, role: user.role, createdAt: user.createdAt }
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Server error during registration" });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if ((!username && !email) || !password) {
            return res.status(400).json({ message: "Provide username/email and password" });
        }

        const user = await User.findOne({ $or: [{ username }, { email }] });
        if (!user) return res.status(404).json({ message: "User not found" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign(
            { id: user._id.toString(), username: user.username, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ message: "Access granted", token });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Server error during login" });
    }
});

app.get("/profile", requireAuth, (req, res) => {
    res.json({ message: "Access granted", user: req.user });
});

app.post("/posts", optionalAuth, async (req, res) => {
    try {
        const { title, content, tags = [], anonymous = false } = req.body;
        if (!title || !content) return res.status(400).json({ message: "title and content are required" });

        const doc = {
            title, content, tags,
            anonymous: !!anonymous,
        };
        if (!anonymous && req.user) {
            doc.author = req.user.id;
        }

        const post = await Post.create(doc);
        res.json({ message: "Post created", post });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Error creating post" });
    }
});

app.get("/posts", async (_req, res) => {
    const posts = await Post.find({}).sort({ createdAt: -1 }).lean();
    res.json(
        posts.map(p => ({
            ...p,
            upvotes: (p.upvoters || []).length,
            downvotes: (p.downvoters || []).length
        }))
    );
});

app.delete("/posts/:id", requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const post = await Post.findById(id);
        if (!post) return res.status(404).json({ message: "Post not found" });

        const isAuthor = post.author && post.author.toString() === req.user.id;
        const isAdmin = req.user.role === "admin";

        if (!isAuthor && !isAdmin) return res.status(403).json({ message: "Not allowed" });

        if (isAdmin && !isAuthor) {
            const { reason } = req.body;
            if (!reason || !reason.trim()) {
                return res.status(400).json({ message: "Admin delete requires a reason" });
            }
            await ModLog.create({
                action: "delete_post",
                targetType: "post",
                targetId: id,
                by: req.user.id,
                reason
            });
        }

        await Post.findByIdAndDelete(id);
        res.json({ message: "Post deleted" });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: "Error deleting post" });
    }
});

app.post("/posts/:id/upvote", requireAuth, async (req, res) => {
    const { id } = req.params;
    const uid = req.user.id;
    const post = await Post.findById(id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    post.downvoters = (post.downvoters || []).filter(x => x.toString() !== uid);
    const already = (post.upvoters || []).some(x => x.toString() === uid);
    post.upvoters = already
        ? post.upvoters.filter(x => x.toString() !== uid)
        : [...(post.upvoters || []), uid];

    await post.save();
    res.json({ message: "Upvote toggled", upvotes: post.upvoters.length, downvotes: post.downvoters.length });
});

app.post("/posts/:id/downvote", requireAuth, async (req, res) => {
    const { id } = req.params;
    const uid = req.user.id;
    const post = await Post.findById(id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    post.upvoters = (post.upvoters || []).filter(x => x.toString() !== uid);
    const already = (post.downvoters || []).some(x => x.toString() === uid);
    post.downvoters = already
        ? post.downvoters.filter(x => x.toString() !== uid)
        : [...(post.downvoters || []), uid];

    await post.save();
    res.json({ message: "Downvote toggled", upvotes: post.upvoters.length, downvotes: post.downvoters.length });
});

app.post("/posts/:id/save", requireAuth, async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const exists = (user.savedPosts || []).some(x => x.toString() === id);
    if (!exists) user.savedPosts.push(id);
    await user.save();

    res.json({ message: "Saved", savedPosts: user.savedPosts });
});

app.delete("/posts/:id/save", requireAuth, async (req, res) => {
    const { id } = req.params;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.savedPosts = (user.savedPosts || []).filter(x => x.toString() !== id);
    await user.save();

    res.json({ message: "Unsaved", savedPosts: user.savedPosts });
});

app.post("/posts/:id/comments", optionalAuth, async (req, res) => {
    const { id } = req.params;
    const { content, anonymous = false } = req.body;
    if (!content) return res.status(400).json({ message: "content is required" });

    const post = await Post.findById(id);
    if (!post) return res.status(404).json({ message: "Post not found" });

    post.comments.push({
        content,
        anonymous: !!anonymous,
        author: (!anonymous && req.user) ? req.user.id : undefined
    });

    await post.save();
    const comment = post.comments[post.comments.length - 1];
    res.json({ message: "Comment added", comment });
});

app.delete("/posts/:postId/comments/:commentId", requireAuth, async (req, res) => {
    const { postId, commentId } = req.params;
    const post = await Post.findById(postId);
    if (!post) return res.status(404).json({ message: "Post not found" });

    const comment = post.comments.id(commentId);
    if (!comment) return res.status(404).json({ message: "Comment not found" });

    const isAuthor = comment.author && comment.author.toString() === req.user.id;
    const isAdmin = req.user.role === "admin";
    if (!isAuthor && !isAdmin) return res.status(403).json({ message: "Not allowed" });

    if (isAdmin && !isAuthor) {
        const { reason } = req.body;
        if (!reason || !reason.trim()) {
            return res.status(400).json({ message: "Admin delete requires a reason" });
        }
        await ModLog.create({
            action: "delete_comment",
            targetType: "comment",
            targetId: commentId,
            by: req.user.id,
            reason
        });
    }

    comment.deleteOne();
    await post.save();
    res.json({ message: "Comment deleted" });
});

app.get("/posts/tags", async (req, res) => {
    try {
        const { tag, tags } = req.query;

        if (!tag && !tags) {
            return res.status(400).json({ message: "Please provide ?tag= or ?tags= in query" });
        }

        let filter = {};
        if (tag) {
            filter.tags = tag;
        } else if (tags) {
            const tagArray = tags.split(",").map(t => t.trim());
            filter.tags = { $in: tagArray };
        }

        const posts = await Post.find(filter).sort({ createdAt: -1 }).lean();

        if (!posts.length) {
            return res.status(404).json({ message: "No posts found for given tag(s)" });
        }

        res.json(
            posts.map(p => ({
                ...p,
                upvotes: (p.upvoters || []).length,
                downvotes: (p.downvoters || []).length,
            }))
        );
    } catch (e) {
        console.error("Error filtering by tags:", e);
        res.status(500).json({ message: "Server error while filtering posts" });
    }
});


app.get("/roadmaps", async (_req, res) => {
    const items = await Roadmap.find({}).sort({ createdAt: -1 });
    res.json(items);
});

app.post("/roadmaps", requireAuth, requireAdmin, async (req, res) => {
    const { title, link, image, content } = req.body;
    if (!title || !link || !image || !content) return res.status(400).json({ message: "All fields required" });
    const doc = await Roadmap.create({ title, link, image, content });
    res.json({ message: "Roadmap added", roadmap: doc });
});

app.delete("/roadmaps/:id", requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    if (!reason || !reason.trim()) return res.status(400).json({ message: "Delete note is required" });

    const doc = await Roadmap.findById(id);
    if (!doc) return res.status(404).json({ message: "Not found" });

    await ModLog.create({
        action: "delete_roadmap",
        targetType: "roadmap",
        targetId: id,
        by: req.user.id,
        reason
    });

    await Roadmap.findByIdAndDelete(id);
    res.json({ message: "Roadmap deleted" });
});

app.get("/repos", async (_req, res) => {
    const items = await Repo.find({}).sort({ createdAt: -1 });
    res.json(items);
});

app.post("/repos", requireAuth, requireAdmin, async (req, res) => {
    const { title, link, image, content } = req.body;
    if (!title || !link || !image || !content) return res.status(400).json({ message: "All fields required" });
    const doc = await Repo.create({ title, link, image, content });
    res.json({ message: "Repo added", repo: doc });
});

app.delete("/repos/:id", requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    if (!reason || !reason.trim()) return res.status(400).json({ message: "Delete note is required" });

    const doc = await Repo.findById(id);
    if (!doc) return res.status(404).json({ message: "Not found" });

    await ModLog.create({
        action: "delete_repo",
        targetType: "repo",
        targetId: id,
        by: req.user.id,
        reason
    });

    await Repo.findByIdAndDelete(id);
    res.json({ message: "Repo deleted" });
});

app.get("/", (_req, res) => res.send("StudentHub backend working"));

if (process.env.VERCEL) {
    module.exports = app;
} else {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

