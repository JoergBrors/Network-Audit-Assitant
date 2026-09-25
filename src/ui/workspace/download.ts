/** Triggers a browser download of a JSON document (no data leaves the browser). */
export function downloadJson(fileName: string, data: unknown): void {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName.replace(/[^\w.-]+/g, "_");
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
