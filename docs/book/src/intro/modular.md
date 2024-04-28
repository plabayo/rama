# 🧱 Modular

> _Modular_, consisting of separate parts or units that can be joined together.
>
> — Some random dictionary.

We advertise _rama_ as a modular service framework to move and transform network packets. It's in fact our tagline. Next to that you can read in [Why Rama](../why_rama.md) that one reason for _rama_ to exist is to allow you to easily
create proxies without having to do everything yourself but while still being
able to write your own code where you wish.

In that spirit we want to emphasise shortly in this chapter that it's
important, as a _rama_ user, to embrace this freedom. In one hand
we want our modular components that we provide to be easy to use,
and flexible where possible. However it would be a mistake to try to make
each building block overly flexible to allow for any possible use case of it.
First of all it would anyway be an impossible never ending task,
and secondly it would seriously impact maintainability and the
Developer Experience (DX).

We hinted before that because of rama you can build proxies without
having to write everything yourself, but that when you want
you can also write your own code. This last part does not only mean
to make your own services and middleware from scratch, but can also
mean that you copy on of ours and modify it to your needs. Doing
so will give for a much cleaner solution then we can ever offer
in a generic manner.

## Modular Example

Let's dive into a real example where we struggled ourselves in finding
this balance between giving enough flexibility and at the same time
keeping it simple enough.

[`rama::service::layer::limit`](https://ramaproxy.org/docs/rama/service/layer/limit/struct.Limit.html) is a generic middleware that allows you to limit what
requests can go through and which not. What this means depends a lot on
the [`Policy`](https://ramaproxy.org/docs/rama/service/layer/limit/policy/trait.Policy.html) used.
You could go as far as adding firewal capabilities to it, even
though we also have the
[`HijackService`](https://ramaproxy.org/docs/rama/service/layer/struct.HijackService.html) for that.

From a consumer of a _service_ wrapped in the `limit` layer there are only two
outcomes:

- the request was able to proceed and you get the `Result` from the inner _service_;
- the request did not go through and you got an error instead from the `Policy` used;

The latter case is also not immediately obvious and requires you to `downcast` the returned error. Simple enough to do however and on you go.

However the story isn't that binary. There is information hidden her that could be useful. Questions you could still reasonably ask are:

- Was the request stuck in the queue (e.g. did it have to retry?)
- How many retries, or put differently, how long was it in the queue?

Depending on your proxy and how you use it, you might even want to expose this
kind of information to your proxy users as to reduce their production speed once
you start to queue, as a way to put backpressure and prevent from requests
being eventually dropped.

For a long time we were wondering, or more aptly put, struggling. Should we also
support these kind of use cases? But then what about the fact that this layer
can be used both as a transport- and application middleware. And so on. Mental torture of the mind if you ask us.

And that brings us back to the topic of modularity, and the mindset one should
have when using `rama`. Reuse when you can, fork and/or create otherwise.
As the maintainers of `rama` we do in fact just the same with the dependencies
we may or may not rely upon. Sometimes it is just a lot easier to embed
a dependency in a more minimal form directly in your codebase then to try
to shoehorn a premade solution into your problem space.

With this we conclude the chapter. And now let's all repeat:

> 🖖 Reuse when you can, fork and/or create otherwise.