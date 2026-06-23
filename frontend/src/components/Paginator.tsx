interface PaginatorProps {
  page: number;
  limit: number;
  totalRecords: number;
  onPageChange: (page: number) => void;
  onLimitChange: (limit: number) => void;
  hasNext: boolean;
  hasPrev: boolean;
  pageSizeOptions?: number[];
}

export function Paginator({
  page,
  limit,
  totalRecords,
  onPageChange,
  onLimitChange,
  hasNext,
  hasPrev,
  pageSizeOptions = [10, 25, 50, 100],
}: PaginatorProps) {
  const totalPages = Math.max(1, Math.ceil(totalRecords / limit));
  const firstRow = totalRecords === 0 ? 0 : (page - 1) * limit + 1;
  const lastRow = Math.min(page * limit, totalRecords);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-surface-border bg-surface-elevated px-3 py-2 text-xs text-slate-300">
      <div>
        Mostrando {firstRow}-{lastRow} de {totalRecords}
      </div>
      <div className="flex items-center gap-2">
        <label htmlFor="page-size" className="text-slate-400">
          Filas
        </label>
        <select
          id="page-size"
          className="rounded border-surface-border bg-slate-900 px-2 py-1 text-xs"
          value={limit}
          onChange={(event) => onLimitChange(Number(event.target.value))}
        >
          {pageSizeOptions.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
        <span className="text-slate-400">
          Pagina {Math.min(page, totalPages)} de {totalPages}
        </span>
        <button
          className="rounded border border-surface-border px-2 py-1 disabled:opacity-40"
          onClick={() => onPageChange(page - 1)}
          disabled={!hasPrev}
        >
          Anterior
        </button>
        <button
          className="rounded border border-surface-border px-2 py-1 disabled:opacity-40"
          onClick={() => onPageChange(page + 1)}
          disabled={!hasNext}
        >
          Siguiente
        </button>
      </div>
    </div>
  );
}

