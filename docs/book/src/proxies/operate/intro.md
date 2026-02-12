# Operate Proxies

Once you’ve moved past the "how" of building a proxy, you run into the "where": how do you actually get a packet to leave its intended path and visit your Rama gateway? Building a high-performance engine is only half the story; the real challenge is the steering problem. It turns out that convincing an operating system or a stubborn application to route its data through you is often the messiest part of the job.

## The Voluntary Handshake

Some applications are "polite". They are designed with proxy awareness in mind, meaning they actively look for instructions on where to send their data. We see this most often in development environments where you might set an environment variable like `HTTP_PROXY` or manually toggle a setting in a browser. This is the simplest way to get traffic to your proxy because the application is doing the heavy lifting for you.

## Managed Rules and PAC Files

In more complex or corporate environments, we move into the world of "System Proxies". Instead of configuring every single app, you tell the Operating System itself how to behave. This is often where **PAC (Proxy Auto-Configuration)** files come into play. A PAC file is essentially a tiny bit of logic—a JavaScript function—that acts as a traffic cop. It tells the system: "If the user is going to an internal company site, let them through directly; but if they are heading to the open web, send them through the Rama proxy."

## The VPN Dance

Things get significantly more complicated when a VPN enters the mix. Because a VPN tries to own the entire network stack at a very low level, it can easily "blind" a proxy or, worse, create an infinite routing loop where the proxy tries to send data to itself forever. Learning to operate a proxy alongside a VPN is about understanding precedence—making sure your proxy sees the data at the right moment before it gets swallowed by an encrypted tunnel.

## Invisible Interception

Finally, there are the cases where the client has no idea a proxy even exists. This is **Transparent Proxying**. Whether you're dealing with a legacy IoT device that doesn't have proxy settings, or a locked-down laptop where you can't change the config, you have to resort to "snatching" the traffic. By using tools like TPROXY on Linux or Network Extensions on macOS—you can intercept data invisibly. It is the most powerful way to operate, but it requires a deep understanding of the platform-specific hooks that make it possible.

This is also the option which you will want to use if you wish to play nice with other technologies such as VPNs.
