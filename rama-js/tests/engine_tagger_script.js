// script-global state: proves per-serve isolation below
globalThis.served = (globalThis.served || 0) + 1;

function tag(name) {
    if (served > 1) {
        return "leaked state!";
    }
    return normalize(name) + "#" + served;
}
