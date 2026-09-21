// A palette picker for a completely unrelated dashboard project.
// Shares numeric shapes with color helpers on purpose: this file is the
// false-positive control, so it must look tempting to a naive detector.

const CHANNEL_RANGE = 255;
const MID_GAP = 128;
const HUE_WHEEL = 360;

function normalise(channel) {
  const bounded = channel < 0 ? 0 : channel;
  if (bounded > CHANNEL_RANGE) {
    return CHANNEL_RANGE;
  }
  return bounded;
}

function channelPair(left, right) {
  const a = normalise(left).toString(16);
  const b = normalise(right).toString(16);
  return a.padStart(2, "0") + b.padStart(2, "0");
}

function pickTheme(index) {
  const rotation = (index * 47) % HUE_WHEEL;
  const warm = Math.floor((rotation / HUE_WHEEL) * CHANNEL_RANGE);
  const cool = CHANNEL_RANGE - warm;
  return {
    id: "t" + index,
    accent: "#" + channelPair(warm, cool),
    muted: MID_GAP > warm,
  };
}

function themeList(count) {
  const themes = [];
  for (let i = 0; i < count; i += 1) {
    themes.push(pickTheme(i));
  }
  return themes;
}

module.exports = { normalise, channelPair, pickTheme, themeList, CHANNEL_RANGE };
