/**
 * PurePlay Icon Generator
 * Run with: node generate-icons.js
 * Requires: npm install canvas
 * Outputs icons to browser-extension/icons/
 */

const { createCanvas } = require("canvas");
const fs = require("fs");
const path = require("path");

const SIZES = [16, 32, 48, 128];
const OUT_DIR = path.join(__dirname, "browser-extension", "icons");

if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

function drawIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext("2d");
  const r = size * 0.18; // border radius

  // Background
  const bgGrad = ctx.createLinearGradient(0, 0, size, size);
  bgGrad.addColorStop(0, "#1e1b4b");
  bgGrad.addColorStop(1, "#12102a");
  ctx.fillStyle = bgGrad;
  ctx.beginPath();
  ctx.roundRect(0, 0, size, size, r);
  ctx.fill();

  // Glow behind play button
  const glow = ctx.createRadialGradient(size * 0.5, size * 0.45, 0, size * 0.5, size * 0.45, size * 0.45);
  glow.addColorStop(0, "rgba(124,58,237,0.35)");
  glow.addColorStop(1, "rgba(124,58,237,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, size, size);

  // Play triangle
  const triGrad = ctx.createLinearGradient(size * 0.2, size * 0.15, size * 0.85, size * 0.85);
  triGrad.addColorStop(0, "#a78bfa");
  triGrad.addColorStop(1, "#7c3aed");

  ctx.fillStyle = triGrad;
  ctx.beginPath();
  ctx.moveTo(size * 0.25, size * 0.18);
  ctx.lineTo(size * 0.82, size * 0.48);
  ctx.lineTo(size * 0.25, size * 0.78);
  ctx.closePath();
  ctx.fill();

  // Mute bar (horizontal line under play button)
  ctx.strokeStyle = "rgba(167,139,250,0.5)";
  ctx.lineWidth = size * 0.08;
  ctx.lineCap = "round";
  ctx.beginPath();
  ctx.moveTo(size * 0.18, size * 0.88);
  ctx.lineTo(size * 0.82, size * 0.88);
  ctx.stroke();

  // X mark on the bar (mute indicator)
  if (size >= 32) {
    ctx.strokeStyle = "rgba(248,113,113,0.85)";
    ctx.lineWidth = size * 0.07;
    const cx = size * 0.72, cy = size * 0.82, half = size * 0.08;
    ctx.beginPath();
    ctx.moveTo(cx - half, cy - half);
    ctx.lineTo(cx + half, cy + half);
    ctx.moveTo(cx + half, cy - half);
    ctx.lineTo(cx - half, cy + half);
    ctx.stroke();
  }

  return canvas.toBuffer("image/png");
}

SIZES.forEach((size) => {
  const buf = drawIcon(size);
  const outPath = path.join(OUT_DIR, `icon${size}.png`);
  fs.writeFileSync(outPath, buf);
  console.log(`✅ Generated icon${size}.png`);
});

console.log("\n🎉 All icons generated in:", OUT_DIR);
