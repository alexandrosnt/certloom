package dnsplugin

// Windows has no group/other mode bits; the agent targets Linux and this only
// lets the tests run on Windows.
const skipPermCheck = true
