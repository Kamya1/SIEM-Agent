type Props = { techniques: string[] };

export function MitreBadge({ techniques }: Props) {
  if (!techniques.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {techniques.map((t) => {
        const parts = t.split(".");
        const base = parts[0];
        const url =
          parts.length > 1
            ? `https://attack.mitre.org/techniques/${base}/${parts[1]}/`
            : `https://attack.mitre.org/techniques/${base}/`;
        return (
          <a
            key={t}
            href={url}
            target="_blank"
            rel="noreferrer"
            className="rounded-md bg-amber-alert/20 px-2 py-0.5 text-[11px] font-mono text-amber-alert ring-1 ring-amber-alert/40 hover:bg-amber-alert/30"
          >
            {t}
          </a>
        );
      })}
    </div>
  );
}
