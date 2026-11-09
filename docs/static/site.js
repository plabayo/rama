// ramaproxy.org — progressive enhancement only; the page works without this file.

(() => {
    "use strict";

    const motionQuery = window.matchMedia("(prefers-reduced-motion: no-preference)");
    const motionOk = () => motionQuery.matches;

    // ---------- copy buttons ----------

    function initCopyButtons() {
        const status = document.getElementById("copy-status");
        for (const button of document.querySelectorAll(".copy-button[data-copy]")) {
            button.setAttribute("title", "Copy command to clipboard");
            let timer = 0;
            button.addEventListener("click", async () => {
                try {
                    await navigator.clipboard.writeText(button.dataset.copy);
                } catch {
                    return;
                }
                button.classList.add("copied");
                if (status) status.textContent = "Copied to clipboard";
                clearTimeout(timer);
                timer = setTimeout(() => {
                    button.classList.remove("copied");
                    if (status) status.textContent = "";
                }, 2000);
            });
        }
    }

    // ---------- stack scenes ----------

    const SCENES = [
        {
            title: "mitm proxy",
            from: "client",
            to: "upstream",
            layers: [
                ["http connect \u00b7 socks5", "proxy"],
                ["tls mitm relay", "security"],
                ["http capture + inspect", "inspect"],
                ["tls + tcp connector", "transport"],
            ],
            crates: "rama-http \u00b7 rama-tls-boring \u00b7 rama-inspect",
            protocols: ["tcp", "tls", "http", "h2", "ws", "socks5"],
        },
        {
            title: "http/3 interception",
            from: "client",
            to: "upstream",
            layers: [
                ["quic listener", "transport"],
                ["clienthello peek", "routing"],
                ["h3 terminate \u00b7 chosen hosts", "security"],
                ["forward the rest untouched", "relay"],
            ],
            crates: "rama-quic \u00b7 rama-http \u00b7 rama-tls-boring",
            protocols: ["udp", "quic", "tls", "h3", "http"],
        },
        {
            title: "masque proxy",
            from: "client",
            to: "internet",
            layers: [
                ["quic + tls", "transport"],
                ["http/3 extended connect", "protocol"],
                ["connect-udp \u00b7 connect-ip", "masque"],
                ["udp \u00b7 ip relay", "transport"],
            ],
            crates: "rama-masque \u00b7 rama-quic \u00b7 rama-udp",
            protocols: ["udp", "quic", "tls", "h3", "masque"],
        },
        {
            title: "browser-like client",
            from: "your code",
            to: "server",
            layers: [
                ["user-agent emulation", "fingerprint"],
                ["http/1.1 \u00b7 h2 \u00b7 h3", "protocol"],
                ["tls \u00b7 boring", "security"],
                ["dns + tcp \u00b7 quic", "transport"],
            ],
            crates: "rama-ua \u00b7 rama-http \u00b7 rama-tls-boring \u00b7 rama-quic",
            protocols: ["dns", "tcp", "quic", "tls", "http", "h2", "h3"],
        },
        {
            title: "transparent proxy",
            from: "device traffic",
            to: "internet",
            layers: [
                ["network extension \u00b7 wfp \u00b7 tproxy", "os"],
                ["tcp \u00b7 udp flows", "transport"],
                ["tls + http peek", "routing"],
                ["your policy", "service"],
            ],
            crates: "rama-net-apple-networkextension \u00b7 rama-tcp \u00b7 rama-udp",
            protocols: ["apple-ne", "wfp", "tproxy", "tcp", "udp", "tls", "http"],
        },
        {
            title: "edge server",
            from: "client",
            to: "your app \u00b7 php",
            layers: [
                ["tcp \u00b7 quic listener", "transport"],
                ["tls + acme certificates", "security"],
                ["ja4 fingerprint \u00b7 anti-bot", "defence"],
                ["router \u00b7 fastcgi fallback", "http"],
            ],
            crates: "rama-tls-acme \u00b7 rama-http \u00b7 rama-fastcgi",
            protocols: ["tcp", "quic", "tls", "acme", "http", "h2", "h3", "fastcgi"],
        },
        {
            title: "socks5 proxy",
            from: "client",
            to: "upstream",
            layers: [
                ["tcp \u00b7 udp listener", "transport"],
                ["socks5 handshake", "proxy"],
                ["tls peek router", "routing"],
                ["relay", "transport"],
            ],
            crates: "rama-socks5 \u00b7 rama-tls \u00b7 rama-tcp \u00b7 rama-udp",
            protocols: ["tcp", "udp", "socks5", "tls", "dns"],
        },
    ];

    const SCENE_DURATION_MS = 7000;
    const LAYER_STEP_MS = 420;

    function initStackDemo() {
        const demo = document.querySelector(".stack-demo");
        if (!demo) return;

        const stage = demo.querySelector(".stack-stage");
        const title = demo.querySelector(".stack-title");
        const flow = demo.querySelector(".stack-flow");
        const crates = demo.querySelector(".stack-crates");
        const tabs = [...demo.querySelectorAll(".stack-tabs button")];
        const protocols = [...demo.querySelectorAll(".stack-protocols li")];

        let current = 0;
        let userPicked = false;
        let hovered = false;
        let visible = true;
        let sceneTimer = 0;
        let litTimers = [];

        const progress = demo.querySelector(".stack-progress");
        demo.style.setProperty("--scene-ms", `${SCENE_DURATION_MS}ms`);

        function setCycling(on) {
            if (!progress) return;
            progress.classList.remove("is-running");
            if (on) {
                void progress.offsetWidth;
                progress.classList.add("is-running");
            }
        }

        function clearLit() {
            litTimers.forEach(clearTimeout);
            litTimers = [];
        }

        function render(index) {
            const scene = SCENES[index];
            current = index;
            title.textContent = scene.title;
            crates.textContent = scene.crates;

            const items = [];
            const start = document.createElement("li");
            start.className = "endpoint";
            start.textContent = scene.from;
            items.push(start);
            scene.layers.forEach(([name, kind], i) => {
                const li = document.createElement("li");
                li.className = "layer";
                li.style.setProperty("--i", String(i));
                const n = document.createElement("span");
                n.textContent = name;
                const k = document.createElement("span");
                k.className = "kind";
                k.textContent = kind;
                li.append(n, k);
                items.push(li);
            });
            const end = document.createElement("li");
            end.className = "endpoint";
            end.textContent = scene.to;
            items.push(end);
            flow.replaceChildren(...items);

            for (const tab of tabs) {
                tab.setAttribute("aria-pressed", String(Number(tab.dataset.scene) === index));
            }
            const on = new Set(scene.protocols);
            for (const p of protocols) p.classList.toggle("on", on.has(p.dataset.p));

            applyMotionState();
        }

        function animateLayers() {
            clearLit();
            const layers = [...flow.querySelectorAll(".layer")];
            layers.forEach((li, i) => {
                litTimers.push(setTimeout(() => li.classList.add("is-lit"), 250 + i * LAYER_STEP_MS));
            });
            stage.classList.remove("is-entering");
            // restart the entry keyframes
            void stage.offsetWidth;
            stage.classList.add("is-entering");
        }

        function applyMotionState() {
            clearLit();
            clearTimeout(sceneTimer);
            if (!motionOk()) {
                setCycling(false);
                demo.classList.add("is-static");
                stage.classList.remove("is-entering");
                return;
            }
            demo.classList.remove("is-static");
            animateLayers();
            const cycling = !userPicked && !hovered && visible;
            setCycling(cycling);
            if (cycling) {
                sceneTimer = setTimeout(() => render((current + 1) % SCENES.length), SCENE_DURATION_MS);
            }
        }

        for (const tab of tabs) {
            tab.addEventListener("click", () => {
                userPicked = true;
                render(Number(tab.dataset.scene));
            });
        }

        // the reader is looking: hold the current scene
        demo.addEventListener("pointerenter", () => {
            hovered = true;
            clearTimeout(sceneTimer);
            setCycling(false);
        });
        demo.addEventListener("pointerleave", () => {
            hovered = false;
            if (motionOk() && !userPicked && visible) applyMotionState();
        });
        demo.addEventListener("focusin", () => {
            hovered = true;
            clearTimeout(sceneTimer);
            setCycling(false);
        });
        demo.addEventListener("focusout", () => {
            hovered = false;
        });

        new IntersectionObserver((entries) => {
            visible = entries.some((e) => e.isIntersecting);
            if (visible) applyMotionState();
            else clearTimeout(sceneTimer);
        }).observe(demo);

        motionQuery.addEventListener("change", applyMotionState);
        render(0);
    }

    // ---------- page-wide network background ----------
    // every device is part of the network. It lives only in the free space between
    // content blocks and never draws under text or controls.

    const DEVICES = [
        "laptop", "phone", "tablet", "desktop", "server", "cloud",
        "router", "firewall", "satellite", "fridge", "watch", "camera",
    ];
    const NODE_STEP = 120;
    const NODE_KEEP = 0.55;
    const NODE_CLEARANCE = 30;
    const LINK_CLEARANCE = 14;
    const REROUTE_MS = 2600;
    const GROW_S = 0.9;
    const HOP_PAUSE_S = 0.35;
    const GLYPH_SCALE = 1.2;

    // blocks the network must stay away from
    const NO_GO = [
        ".site-nav", ".site-footer",
        ".hero-copy", ".stack-demo",
        "main > section > *",
        "main > section > div > *",
    ].join(", ");

    const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

    function docRect(el, pad) {
        let x = 0;
        let y = 0;
        // offsets ignore transforms, so entry animations don't skew the measurement
        for (let e = el; e; e = e.offsetParent) {
            x += e.offsetLeft;
            y += e.offsetTop;
        }
        return { x0: x - pad, y0: y - pad, x1: x + el.offsetWidth + pad, y1: y + el.offsetHeight + pad };
    }

    function segmentHitsRect(ax, ay, bx, by, r) {
        // only axis-aligned segments are used, so a box test is exact
        const x0 = Math.min(ax, bx);
        const x1 = Math.max(ax, bx);
        const y0 = Math.min(ay, by);
        const y1 = Math.max(ay, by);
        return x1 > r.x0 && x0 < r.x1 && y1 > r.y0 && y0 < r.y1;
    }

    function routePoints(a, b, horizontalFirst) {
        // right-angled route with a rounded corner, sampled as a polyline
        const corner = horizontalFirst ? { x: b.x, y: a.y } : { x: a.x, y: b.y };
        const radius = Math.min(10, Math.abs(b.x - a.x) / 2, Math.abs(b.y - a.y) / 2);
        if (radius < 1) return [a, b];
        const inDir = { x: Math.sign(corner.x - a.x), y: Math.sign(corner.y - a.y) };
        const outDir = { x: Math.sign(b.x - corner.x), y: Math.sign(b.y - corner.y) };
        const p0 = { x: corner.x - inDir.x * radius, y: corner.y - inDir.y * radius };
        const p1 = { x: corner.x + outDir.x * radius, y: corner.y + outDir.y * radius };
        const pts = [{ x: a.x, y: a.y }, p0];
        for (let i = 1; i < 6; i++) {
            const t = i / 6;
            const u = 1 - t;
            // quadratic bezier through the corner
            pts.push({
                x: u * u * p0.x + 2 * u * t * corner.x + t * t * p1.x,
                y: u * u * p0.y + 2 * u * t * corner.y + t * t * p1.y,
            });
        }
        pts.push(p1, { x: b.x, y: b.y });
        return pts;
    }

    function withLengths(pts) {
        const cum = [0];
        for (let i = 1; i < pts.length; i++) {
            cum.push(cum[i - 1] + Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y));
        }
        return { pts, cum, len: cum[cum.length - 1] };
    }

    function pointAt(path, s) {
        const { pts, cum } = path;
        if (s <= 0) return pts[0];
        for (let i = 1; i < pts.length; i++) {
            if (cum[i] >= s) {
                const t = (s - cum[i - 1]) / (cum[i] - cum[i - 1] || 1);
                return { x: pts[i - 1].x + (pts[i].x - pts[i - 1].x) * t, y: pts[i - 1].y + (pts[i].y - pts[i - 1].y) * t };
            }
        }
        return pts[pts.length - 1];
    }

    function initNetwork() {
        const canvas = document.querySelector(".net-canvas");
        if (!canvas || !canvas.getContext) return;
        const ctx = canvas.getContext("2d");
        const nav = document.querySelector(".site-nav");

        let vw = 0;
        let vh = 0;
        let nodes = [];
        let links = [];
        let packets = [];
        let rafId = 0;
        let lastTime = 0;
        let rerouteAt = 0;
        let staticDirty = true;

        function build() {
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            vw = window.innerWidth;
            vh = window.innerHeight;
            canvas.width = Math.round(vw * dpr);
            canvas.height = Math.round(vh * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

            const docW = document.documentElement.clientWidth;
            const docH = document.documentElement.scrollHeight;
            const nodeZones = [...document.querySelectorAll(NO_GO)].map((el) => docRect(el, NODE_CLEARANCE));
            const linkZones = [...document.querySelectorAll(NO_GO)].map((el) => docRect(el, LINK_CLEARANCE));
            const free = (x, y) => x > 14 && x < docW - 14 && !nodeZones.some((r) => x > r.x0 && x < r.x1 && y > r.y0 && y < r.y1);

            nodes = [];
            for (let y = NODE_STEP / 2; y < docH; y += NODE_STEP / 2) {
                for (let x = NODE_STEP / 3; x < docW; x += NODE_STEP / 2) {
                    if (Math.random() > NODE_KEEP * 0.5) continue;
                    const nx = Math.round(x + (Math.random() - 0.5) * NODE_STEP * 0.4);
                    const ny = Math.round(y + (Math.random() - 0.5) * NODE_STEP * 0.4);
                    if (!free(nx, ny)) continue;
                    if (nodes.some((n) => Math.hypot(n.x - nx, n.y - ny) < NODE_STEP * 0.6)) continue;
                    nodes.push({
                        x: nx,
                        y: ny,
                        kind: DEVICES[Math.floor(Math.random() * DEVICES.length)],
                        links: [],
                        pulse: 0,
                        appear: 0,
                        delay: Math.random() * 0.8,
                    });
                }
            }

            // candidate routes to near neighbours, only where the whole route is clear
            links = [];
            const seen = new Set();
            nodes.forEach((a, ai) => {
                nodes
                    .map((b, bi) => [b, bi, Math.hypot(a.x - b.x, a.y - b.y)])
                    .filter(([b, , d]) => b !== a && d < NODE_STEP * 2.4)
                    .sort((p, q) => p[2] - q[2])
                    .slice(0, 3)
                    .forEach(([b, bi]) => {
                        const key = ai < bi ? `${ai}-${bi}` : `${bi}-${ai}`;
                        if (seen.has(key)) return;
                        seen.add(key);
                        for (const horizontalFirst of [Math.random() < 0.5, true, false]) {
                            const pts = routePoints(a, b, horizontalFirst);
                            const clear = pts.every((p, i) => i === 0 || !linkZones.some((r) => segmentHitsRect(pts[i - 1].x, pts[i - 1].y, p.x, p.y, r)));
                            if (!clear) continue;
                            const up = Math.random() < 0.55;
                            const link = { a, b, path: withLengths(pts), up, grow: up ? 1 : 0, origin: a, heat: 0 };
                            links.push(link);
                            a.links.push(link);
                            b.links.push(link);
                            break;
                        }
                    });
            });

            nodes = nodes.filter((n) => n.links.length);
            packets = [];
            staticDirty = true;
        }

        const usable = (l) => l.up && l.grow > 0.98;
        const other = (l, n) => (l.a === n ? l.b : l.a);

        function inView(y, top, margin = 60) {
            return y > top - margin && y < top + vh + margin;
        }

        function reroute(top) {
            // a device near the screen drops one route and brings up another
            const hubs = nodes.filter((n) => inView(n.y, top, 0) && n.links.length > 1);
            if (!hubs.length) return;
            const hub = hubs[Math.floor(Math.random() * hubs.length)];
            const up = hub.links.filter((l) => l.up);
            const down = hub.links.filter((l) => !l.up);
            if (up.length > 1 || (up.length && down.length)) {
                const drop = up[Math.floor(Math.random() * up.length)];
                drop.up = false;
                drop.origin = hub;
            }
            if (down.length) {
                const add = down[Math.floor(Math.random() * down.length)];
                add.up = true;
                add.origin = hub;
            }
        }

        function spawn(top) {
            const starts = nodes.filter((n) => inView(n.y, top, 0) && n.links.some(usable));
            if (!starts.length) return null;
            const from = starts[Math.floor(Math.random() * starts.length)];
            const options = from.links.filter(usable);
            const link = options[Math.floor(Math.random() * options.length)];
            return { from, link, t: 0, wait: 0, hops: 3 + Math.floor(Math.random() * 5), speed: 70 + Math.random() * 40 };
        }

        function arrive(p) {
            const at = other(p.link, p.from);
            at.pulse = 1;
            p.hops -= 1;
            const options = at.links.filter((l) => usable(l) && l !== p.link);
            if (p.hops <= 0 || !options.length) return false;
            p.from = at;
            p.link = options[Math.floor(Math.random() * options.length)];
            p.t = 0;
            p.wait = HOP_PAUSE_S;
            return true;
        }

        function packetPos(p, t) {
            const path = p.link.path;
            const s = path.len * t;
            return pointAt(path, p.from === p.link.a ? s : path.len - s);
        }

        function glyph(kind, gx, gy, scale) {
            ctx.save();
            ctx.translate(gx, gy);
            ctx.scale(scale, scale);
            ctx.lineWidth = 1 / scale;
            const x = 0;
            const y = 0;
            ctx.beginPath();
            switch (kind) {
                case "laptop":
                    ctx.rect(x - 7, y - 6, 14, 9);
                    ctx.moveTo(x - 9.5, y + 5);
                    ctx.lineTo(x + 9.5, y + 5);
                    break;
                case "phone":
                    ctx.roundRect(x - 4, y - 7, 8, 14, 2);
                    ctx.moveTo(x - 1, y + 4.5);
                    ctx.lineTo(x + 1, y + 4.5);
                    break;
                case "tablet":
                    ctx.roundRect(x - 6, y - 8, 12, 16, 2);
                    ctx.moveTo(x - 0.5, y + 6);
                    ctx.lineTo(x + 0.5, y + 6);
                    break;
                case "desktop":
                    ctx.rect(x - 8, y - 7, 16, 10);
                    ctx.moveTo(x, y + 3);
                    ctx.lineTo(x, y + 6);
                    ctx.moveTo(x - 4, y + 6.5);
                    ctx.lineTo(x + 4, y + 6.5);
                    break;
                case "server":
                    ctx.rect(x - 7, y - 8, 14, 5);
                    ctx.rect(x - 7, y - 2.5, 14, 5);
                    ctx.rect(x - 7, y + 3, 14, 5);
                    break;
                case "cloud":
                    ctx.moveTo(x - 8, y + 4);
                    ctx.arc(x - 4, y + 1, 3.5, Math.PI * 0.6, Math.PI * 1.5);
                    ctx.arc(x + 1, y - 2, 5, Math.PI * 1.1, Math.PI * 1.95);
                    ctx.arc(x + 5.5, y + 1.5, 3, Math.PI * 1.5, Math.PI * 0.5);
                    ctx.lineTo(x - 4.5, y + 4.5);
                    break;
                case "router":
                    ctx.rect(x - 8, y, 16, 5);
                    ctx.moveTo(x - 4, y);
                    ctx.lineTo(x - 6, y - 6);
                    ctx.moveTo(x + 4, y);
                    ctx.lineTo(x + 6, y - 6);
                    break;
                case "firewall":
                    ctx.rect(x - 8, y - 6, 16, 12);
                    ctx.moveTo(x - 8, y - 2);
                    ctx.lineTo(x + 8, y - 2);
                    ctx.moveTo(x - 8, y + 2);
                    ctx.lineTo(x + 8, y + 2);
                    ctx.moveTo(x - 2, y - 6);
                    ctx.lineTo(x - 2, y - 2);
                    ctx.moveTo(x + 3, y - 2);
                    ctx.lineTo(x + 3, y + 2);
                    ctx.moveTo(x - 3, y + 2);
                    ctx.lineTo(x - 3, y + 6);
                    break;
                case "satellite":
                    ctx.rect(x - 2.5, y - 2.5, 5, 5);
                    ctx.rect(x - 10, y - 2, 6, 4);
                    ctx.rect(x + 4, y - 2, 6, 4);
                    ctx.moveTo(x, y - 2.5);
                    ctx.lineTo(x, y - 6);
                    break;
                case "fridge":
                    ctx.roundRect(x - 5, y - 9, 10, 18, 1.5);
                    ctx.moveTo(x - 5, y - 3);
                    ctx.lineTo(x + 5, y - 3);
                    ctx.moveTo(x + 3, y - 7);
                    ctx.lineTo(x + 3, y - 5);
                    ctx.moveTo(x + 3, y - 1);
                    ctx.lineTo(x + 3, y + 3);
                    break;
                case "watch":
                    ctx.roundRect(x - 4, y - 4.5, 8, 9, 2);
                    ctx.moveTo(x - 2.5, y - 4.5);
                    ctx.lineTo(x - 2.5, y - 8);
                    ctx.moveTo(x + 2.5, y - 4.5);
                    ctx.lineTo(x + 2.5, y - 8);
                    ctx.moveTo(x - 2.5, y + 4.5);
                    ctx.lineTo(x - 2.5, y + 8);
                    ctx.moveTo(x + 2.5, y + 4.5);
                    ctx.lineTo(x + 2.5, y + 8);
                    break;
                case "camera":
                    ctx.rect(x - 7, y - 4, 11, 8);
                    ctx.moveTo(x + 4, y - 1.5);
                    ctx.lineTo(x + 8, y - 4);
                    ctx.lineTo(x + 8, y + 4);
                    ctx.lineTo(x + 4, y + 1.5);
                    break;
            }
            ctx.stroke();
            ctx.restore();
        }

        function strokeLink(l, top, amount) {
            // draw `amount` of the route, starting at its origin end
            const path = l.path;
            const fromA = l.origin === l.a;
            const want = path.len * amount;
            ctx.beginPath();
            let walked = 0;
            const pts = fromA ? path.pts : [...path.pts].reverse();
            ctx.moveTo(pts[0].x, pts[0].y - top);
            for (let i = 1; i < pts.length; i++) {
                const seg = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
                if (walked + seg >= want) {
                    const t = (want - walked) / (seg || 1);
                    ctx.lineTo(pts[i - 1].x + (pts[i].x - pts[i - 1].x) * t, pts[i - 1].y + (pts[i].y - pts[i - 1].y) * t - top);
                    break;
                }
                walked += seg;
                ctx.lineTo(pts[i].x, pts[i].y - top);
            }
            ctx.stroke();
        }

        function draw(dt, now) {
            const top = window.scrollY;
            const navH = nav ? nav.offsetHeight : 0;
            ctx.clearRect(0, 0, vw, vh);
            ctx.save();
            ctx.beginPath();
            ctx.rect(0, navH, vw, vh - navH);
            ctx.clip();

            const moving = dt > 0;
            if (moving && now >= rerouteAt) {
                reroute(top);
                rerouteAt = now + REROUTE_MS * (0.7 + Math.random() * 0.6);
            }

            ctx.lineWidth = 1;
            ctx.lineCap = "round";
            for (const l of links) {
                const target = l.up ? 1 : 0;
                if (!moving) l.grow = target;
                else if (l.grow !== target) {
                    l.grow = Math.max(0, Math.min(1, l.grow + (target ? 1 : -1) * (dt / GROW_S)));
                }
                if (l.heat > 0) l.heat = Math.max(0, l.heat - dt * 0.6);
                if (l.grow <= 0) continue;
                if (!inView(l.a.y, top, 400) && !inView(l.b.y, top, 400)) continue;
                const shown = Math.min(l.a.appear, l.b.appear);
                const amount = easeInOut(l.grow) * (moving ? shown : 1);
                if (amount <= 0) continue;
                ctx.strokeStyle = "rgba(140, 158, 142, 0.075)";
                strokeLink(l, top, amount);
                if (l.heat > 0) {
                    ctx.strokeStyle = `rgba(0, 200, 0, ${0.16 * l.heat})`;
                    strokeLink(l, top, amount);
                }
            }

            for (let i = packets.length - 1; i >= 0; i--) {
                const p = packets[i];
                if (p.wait > 0) {
                    p.wait -= dt;
                } else {
                    p.t += (p.speed * dt) / (p.link.path.len || 1);
                    p.link.heat = 1;
                    if (p.t >= 1 && !arrive(p)) {
                        packets.splice(i, 1);
                        continue;
                    }
                }
                const e = easeInOut(Math.min(1, p.t));
                for (let k = 3; k >= 0; k--) {
                    // short fading trail behind the packet
                    const back = Math.max(0, e - (k * 10) / (p.link.path.len || 1));
                    const pos = packetPos(p, back);
                    ctx.fillStyle = `rgba(0, 200, 0, ${k === 0 ? 0.7 : 0.18 / k})`;
                    const size = k === 0 ? 2.6 : 2;
                    ctx.fillRect(pos.x - size / 2, pos.y - top - size / 2, size, size);
                }
            }

            for (const n of nodes) {
                if (!inView(n.y, top)) continue;
                if (moving) {
                    if (n.delay > 0) n.delay -= dt;
                    else if (n.appear < 1) n.appear = Math.min(1, n.appear + dt / 0.7);
                    if (n.pulse > 0) n.pulse = Math.max(0, n.pulse - dt * 1.1);
                } else {
                    n.appear = 1;
                }
                const a = easeInOut(n.appear);
                if (a <= 0) continue;
                const p = n.pulse;
                const r = Math.round(150 * (1 - p));
                const g = Math.round(165 + 35 * p);
                const b = Math.round(152 * (1 - p));
                ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${(0.2 + 0.38 * p) * a})`;
                glyph(n.kind, n.x, n.y - top, GLYPH_SCALE * (0.85 + 0.15 * a));
            }

            ctx.restore();

            const target = Math.min(10, Math.max(3, Math.round((vw * vh) / 140000)));
            if (moving && packets.length < target && Math.random() < 0.05) {
                const p = spawn(top);
                if (p) packets.push(p);
            }
        }

        function loop(now) {
            const dt = Math.min(0.25, (now - lastTime) / 1000 || 0);
            lastTime = now;
            draw(dt, now);
            rafId = requestAnimationFrame(loop);
        }

        function drawStatic() {
            staticDirty = false;
            draw(0, 0);
        }

        function start() {
            cancelAnimationFrame(rafId);
            rafId = 0;
            build();
            if (!motionOk()) {
                drawStatic(); // still picture that scrolls with the page
                return;
            }
            lastTime = performance.now();
            rerouteAt = lastTime + REROUTE_MS;
            rafId = requestAnimationFrame(loop);
        }

        window.addEventListener(
            "scroll",
            () => {
                if (rafId || staticDirty) return;
                staticDirty = true;
                requestAnimationFrame(drawStatic);
            },
            { passive: true },
        );

        let resizeTimer = 0;
        let lastSize = "";
        new ResizeObserver(() => {
            const size = `${window.innerWidth}x${document.documentElement.scrollHeight}`;
            if (size === lastSize) return;
            lastSize = size;
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(start, 200);
        }).observe(document.body);

        motionQuery.addEventListener("change", start);
        start();
    }

    // ---------- layer flow (modularity) ----------

    const HOP_MS = 520;
    const ROUND_PAUSE_MS = 1100;

    function initLayerFlow() {
        const flow = document.querySelector(".layer-flow");
        if (!flow) return;

        const slabs = [...flow.querySelectorAll(".slab")];
        const packet = flow.querySelector(".rail-packet");
        const core = slabs.length - 1;
        // request hops in to the service, the response hops back out
        const path = [];
        for (let i = 0; i <= core; i++) path.push([i, false]);
        for (let i = core - 1; i >= 0; i--) path.push([i, true]);

        let step = 0;
        let swapNext = 0;
        let timer = 0;
        let visible = false;

        function show(pos, response) {
            slabs.forEach((s, i) => s.classList.toggle("is-active", i === pos));
            flow.classList.toggle("is-response", response);
            if (packet) packet.style.setProperty("--pos", String(pos));
        }

        function swapOption(slab) {
            const options = [...slab.querySelectorAll(".slab-options li")];
            if (options.length < 2) return;
            const at = options.findIndex((o) => o.classList.contains("on"));
            const next = options[(at + 1) % options.length];
            options.forEach((o) => o.classList.toggle("on", o === next));
            if (slab.classList.contains("core")) return;
            const value = slab.querySelector(".slab-value");
            value.textContent = next.textContent;
            value.classList.remove("is-swapping");
            void value.offsetWidth;
            value.classList.add("is-swapping");
        }

        function tick() {
            const [pos, response] = path[step];
            show(pos, response);
            step += 1;
            if (step === path.length) {
                step = 0;
                timer = setTimeout(() => {
                    // keep, swap or write yourself: one layer changes per round trip
                    swapOption(slabs[swapNext]);
                    swapNext = (swapNext + 1) % slabs.length;
                    tick();
                }, ROUND_PAUSE_MS);
                return;
            }
            timer = setTimeout(tick, HOP_MS);
        }

        function stop() {
            clearTimeout(timer);
            timer = 0;
        }

        function start() {
            stop();
            if (!motionOk()) {
                slabs.forEach((s) => s.classList.remove("is-active"));
                flow.classList.remove("is-response");
                if (packet) packet.style.setProperty("--pos", String(core));
                return;
            }
            if (visible) tick();
        }

        new IntersectionObserver((entries) => {
            visible = entries.some((e) => e.isIntersecting);
            if (visible) start();
            else stop();
        }, { threshold: 0.25 }).observe(flow);

        motionQuery.addEventListener("change", start);
    }

    // ---------- scroll cue ----------
    // when the in-page cue sits below the fold, show a compact one in a spot
    // that is free of content; if there is no such spot, show nothing

    function initScrollCue() {
        const inline = document.querySelector(".scroll-cue");
        const float = document.querySelector(".scroll-cue-float");
        if (!inline || !float) return;
        const content = [".site-nav", ".hero-copy > *", ".stack-demo", ".hero-cue", "main > section:not(.home-hero) > *"].join(", ");
        const CLEARANCE = 12;
        let spot = null;

        function overlapsContent(x, y, size) {
            const box = { x0: x - CLEARANCE, y0: y - CLEARANCE, x1: x + size + CLEARANCE, y1: y + size + CLEARANCE };
            return [...document.querySelectorAll(content)].some((el) => {
                const r = el.getBoundingClientRect();
                return r.width && box.x1 > r.left && box.x0 < r.right && box.y1 > r.top && box.y0 < r.bottom;
            });
        }

        function findSpot() {
            if (inline.getBoundingClientRect().bottom <= window.innerHeight) return null;
            const size = float.offsetWidth || 38;
            const y = window.innerHeight - size - 20;
            const copy = document.querySelector(".hero-copy").getBoundingClientRect();
            const demo = document.querySelector(".stack-demo").getBoundingClientRect();
            const candidates = [];
            if (demo.left > copy.right) candidates.push((copy.right + demo.left) / 2 - size / 2);
            candidates.push(window.innerWidth - size - 20);
            for (const x of candidates) {
                if (!overlapsContent(x, y, size)) return { x, y };
            }
            return null;
        }

        function update() {
            const atTop = window.scrollY < 24;
            if (atTop) spot = findSpot();
            if (spot) {
                float.style.left = `${spot.x}px`;
                float.style.top = `${spot.y}px`;
            }
            float.classList.toggle("is-visible", Boolean(spot) && atTop);
        }

        float.addEventListener("click", () => float.classList.remove("is-visible"));
        window.addEventListener("scroll", update, { passive: true });
        window.addEventListener("resize", update);
        // layout settles after fonts and the first scene render
        requestAnimationFrame(() => setTimeout(update, 150));
    }

    function init() {
        initCopyButtons();
        initStackDemo();
        initLayerFlow();
        initScrollCue();
        initNetwork();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
