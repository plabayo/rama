// EventSource bootstrap for the SSE demo page served by
// `/sse` when the client `Accept`s HTML. Subscribes to the same
// `/sse` URL (which returns `text/event-stream` when not asked
// for HTML) and appends each `data:` line as a list item.

let nextId = 0;
const list = document.getElementById("todos");
const statusEl = document.getElementById("status");

const es = new EventSource("/sse");

function addTodo(text) {
    const li = document.createElement("li");

    const id = "todo-" + nextId++;

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = id;

    const label = document.createElement("label");
    label.htmlFor = id;
    label.textContent = text;

    li.appendChild(checkbox);
    li.appendChild(label);
    list.appendChild(li);
}

es.onopen = () => {
    statusEl.textContent = "Connected";
};
es.onerror = () => {
    es.close();
    statusEl.textContent = "Disconnected";
};

es.onmessage = (ev) => {
    if (!ev.data) return;
    addTodo(ev.data);
};
