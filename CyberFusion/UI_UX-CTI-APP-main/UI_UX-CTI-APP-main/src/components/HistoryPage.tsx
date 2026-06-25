import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import {
  Download,
  Loader2,
  FileText,
  Search,
  RefreshCw,
  FileDown,
  ChevronLeft,
  ChevronRight,
  Wifi,
  WifiOff,
} from "lucide-react";
import { toast } from "sonner";

/* ── Types ── */
interface HistoryEntry {
  reportId: string;
  username: string;
  email: string;
  ioc: string;
  iocType: string;
  threatLevel: string;
  aiAnalysis: string;
  createdAt: string;
}

interface HistoryPageProps {
  accessToken: string;
  apiBaseUrl: string;
}

/* ── Constants ── */
const WS_URL = "ws://localhost:5000/ws";
const PAGE_SIZE = 10;

/* ── Helpers ── */
const threatColor = (level: string) => {
  const l = level?.toUpperCase();

  if (l === "CRITICAL") return "destructive";
  if (l === "HIGH") return "destructive";
  if (l === "MEDIUM") return "default";

  return "secondary";
};

const typeIcon = (type: string) => {
  if (type?.includes("hash")) return "🔐";
  if (type === "ip") return "🌐";
  if (type === "domain") return "🔗";
  if (type === "url") return "🔒";
  if (type === "subnet") return "📡";
  if (type === "asn") return "🏢";

  return "🔍";
};

/* ════════════════════════════════════
   COMPONENT
════════════════════════════════════ */
export function HistoryPage({ accessToken, apiBaseUrl }: HistoryPageProps) {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [wsConnected, setWsConnected] = useState(false);
  const [downloading, setDownloading] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  /* ── Fetch initial history ── */
  const fetchHistory = useCallback(async () => {
    if (!accessToken) {
      console.warn("[history] accessToken is empty");
      setHistory([]);
      setLoading(false);
      return;
    }

    setLoading(true);

    try {
      const res = await fetch(`${apiBaseUrl}/history`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to load history");
      }

      if (data.success) {
        setHistory(data.history || []);
      } else {
        toast.error(data.error || "Failed to load history");
      }
    } catch (err: any) {
      console.error("[history]", err);
      toast.error(err.message || "Cannot connect to server");
    } finally {
      setLoading(false);
    }
  }, [apiBaseUrl, accessToken]);

  /* ── WebSocket ── */
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    if (wsRef.current?.readyState === WebSocket.CONNECTING) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      console.log("[WS] Connected to history feed");
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === "NEW_REPORT") {
          const entry: HistoryEntry = msg.data;

          setHistory((prev) => {
            if (prev.some((e) => e.reportId === entry.reportId)) {
              return prev;
            }

            return [entry, ...prev];
          });

          toast.success(`New report: ${entry.reportId} (${entry.ioc})`);
        }
      } catch (e) {
        console.warn("[WS] Bad message", e);
      }
    };

    ws.onerror = () => {
      setWsConnected(false);
    };

    ws.onclose = () => {
      setWsConnected(false);

      reconnectTimerRef.current = window.setTimeout(() => {
        connectWS();
      }, 3000);
    };
  }, []);

  useEffect(() => {
    fetchHistory();
    connectWS();

    return () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }

      wsRef.current?.close();
    };
  }, [fetchHistory, connectWS]);

  /* ── Download handler ── */
  const handleDownload = async (
    entry: HistoryEntry,
    format: "pdf" | "docx",
  ) => {
    setDownloading(`${entry.reportId}-${format}`);

    try {
      const res = await fetch(`${apiBaseUrl}/api/export`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          content: entry.aiAnalysis,
          format,
        }),
      });

      if (!res.ok) {
        throw new Error("Export failed");
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `${entry.reportId}.${format}`;
      a.click();

      URL.revokeObjectURL(url);

      toast.success(`Downloaded ${entry.reportId}.${format.toUpperCase()}`);
    } catch (err) {
      console.error(err);
      toast.error("Download failed");
    } finally {
      setDownloading(null);
    }
  };

  /* ── Filter & Pagination ── */
  const filtered = history.filter((e) => {
    const q = searchQuery.toLowerCase();

    if (!q) return true;

    return (
      e.reportId?.toLowerCase().includes(q) ||
      e.username?.toLowerCase().includes(q) ||
      e.email?.toLowerCase().includes(q) ||
      e.ioc?.toLowerCase().includes(q) ||
      e.iocType?.toLowerCase().includes(q) ||
      e.threatLevel?.toLowerCase().includes(q)
    );
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);

  const paginated = filtered.slice(
    (safePage - 1) * PAGE_SIZE,
    safePage * PAGE_SIZE,
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  return (
    <div className="space-y-6 px-2 sm:px-0">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1
            className="text-2xl sm:text-3xl lg:text-4xl"
            style={{
              fontWeight: "var(--font-weight-bold)",
              letterSpacing: "-0.02em",
              marginBottom: "0.5rem",
            }}
          >
            Analysis History
          </h1>

          <p className="text-muted-foreground text-sm sm:text-base">
            Real-time log of AI-generated threat intelligence reports
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={`flex items-center gap-1 text-xs px-2 py-1 rounded-full border ${
              wsConnected
                ? "bg-green-50 text-green-700 border-green-200"
                : "bg-red-50 text-red-700 border-red-200"
            }`}
          >
            {wsConnected ? (
              <>
                <Wifi className="h-3 w-3" /> Live
              </>
            ) : (
              <>
                <WifiOff className="h-3 w-3" /> Disconnected
              </>
            )}
          </span>

          <Button
            size="sm"
            variant="outline"
            onClick={fetchHistory}
            disabled={loading}
          >
            <RefreshCw
              className={`h-4 w-4 mr-1 ${loading ? "animate-spin" : ""}`}
            />
            Refresh
          </Button>
        </div>
      </div>

      {/* Search */}
      <div style={{ position: "relative" }}>
        <Search
          style={{
            position: "absolute",
            left: "12px",
            top: "50%",
            transform: "translateY(-50%)",
            width: "16px",
            height: "16px",
            color: "#9ca3af",
            pointerEvents: "none",
          }}
        />

        <input
          type="text"
          placeholder="Search by Report ID, Username, IOC, Type, or Threat Level..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            width: "100%",
            paddingLeft: "40px",
            paddingRight: searchQuery ? "40px" : "12px",
            height: "40px",
            borderRadius: "8px",
            border: "1px solid #d1d5db",
            backgroundColor: "#ffffff",
            fontSize: "14px",
            boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
            outline: "none",
          }}
          onFocus={(e) => {
            e.target.style.border = "1px solid #3b82f6";
            e.target.style.boxShadow = "0 0 0 3px rgba(59,130,246,0.15)";
          }}
          onBlur={(e) => {
            e.target.style.border = "1px solid #d1d5db";
            e.target.style.boxShadow = "0 1px 2px rgba(0,0,0,0.05)";
          }}
        />

        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            style={{
              position: "absolute",
              right: "12px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "#9ca3af",
              background: "none",
              border: "none",
              cursor: "pointer",
              fontSize: "14px",
            }}
          >
            ✕
          </button>
        )}
      </div>

      {/* Stats summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total Reports", value: history.length },
          { label: "Filtered", value: filtered.length },
          {
            label: "Critical / High",
            value: history.filter((e) =>
              ["CRITICAL", "HIGH"].includes(e.threatLevel?.toUpperCase()),
            ).length,
          },
          { label: "This Page", value: paginated.length },
        ].map((s) => (
          <Card key={s.label} className="py-3">
            <CardContent className="p-3">
              <p className="text-xs text-muted-foreground">{s.label}</p>
              <p className="text-2xl font-bold">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Table Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
            <FileText className="h-5 w-5" />
            Downloaded Reports
          </CardTitle>

          <CardDescription className="text-xs sm:text-sm">
            Click Download to re-export any report as PDF or DOCX
          </CardDescription>
        </CardHeader>

        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center h-40 gap-2 text-muted-foreground">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span className="text-sm">Loading history...</span>
            </div>
          ) : paginated.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 gap-2 text-muted-foreground">
              <FileText className="h-10 w-10 opacity-40" />
              <p className="text-sm">
                {searchQuery
                  ? "No results match your search."
                  : "No analysis history yet."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs w-10">#</TableHead>
                    <TableHead className="text-xs">Report ID</TableHead>
                    <TableHead className="text-xs">Username</TableHead>
                    <TableHead className="text-xs">Date</TableHead>
                    <TableHead className="text-xs">IOC</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">Threat</TableHead>
                    <TableHead className="text-xs text-center">
                      Actions
                    </TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {paginated.map((entry, idx) => {
                    const rowNum = (safePage - 1) * PAGE_SIZE + idx + 1;
                    const pdfKey = `${entry.reportId}-pdf`;
                    const docxKey = `${entry.reportId}-docx`;

                    return (
                      <TableRow key={entry.reportId}>
                        <TableCell className="text-xs text-muted-foreground">
                          {rowNum}
                        </TableCell>

                        <TableCell>
                          <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">
                            {entry.reportId}
                          </code>
                        </TableCell>

                        <TableCell>
                          <div className="flex flex-col">
                            <span className="text-xs font-semibold">
                              {entry.username}
                            </span>
                            <span className="text-xs text-muted-foreground truncate max-w-[140px]">
                              {entry.email}
                            </span>
                          </div>
                        </TableCell>

                        <TableCell className="text-xs whitespace-nowrap">
                          {new Date(entry.createdAt).toLocaleString("id-ID", {
                            day: "2-digit",
                            month: "short",
                            year: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </TableCell>

                        <TableCell>
                          <span
                            className="text-xs font-mono max-w-[160px] block truncate"
                            title={entry.ioc}
                          >
                            {entry.ioc}
                          </span>
                        </TableCell>

                        <TableCell>
                          <Badge variant="outline" className="text-xs gap-1">
                            {typeIcon(entry.iocType)}
                            {entry.iocType?.toUpperCase()}
                          </Badge>
                        </TableCell>

                        <TableCell>
                          <Badge
                            variant={threatColor(entry.threatLevel)}
                            className="text-xs"
                          >
                            {entry.threatLevel || "N/A"}
                          </Badge>
                        </TableCell>

                        <TableCell>
                          <div className="flex items-center gap-1.5 justify-center">
                            <Button
                              size="sm"
                              variant="default"
                              className="h-7 px-2 text-xs gap-1"
                              disabled={downloading === pdfKey}
                              onClick={() => handleDownload(entry, "pdf")}
                            >
                              {downloading === pdfKey ? (
                                <Loader2 className="h-3 w-3 animate-spin" />
                              ) : (
                                <FileDown className="h-3 w-3" />
                              )}
                              PDF
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2 text-xs gap-1"
                              disabled={downloading === docxKey}
                              onClick={() => handleDownload(entry, "docx")}
                            >
                              {downloading === docxKey ? (
                                <Loader2 className="h-3 w-3 animate-spin" />
                              ) : (
                                <Download className="h-3 w-3" />
                              )}
                              DOCX
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Pagination */}
          {!loading && filtered.length > PAGE_SIZE && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t">
              <p className="text-xs text-muted-foreground">
                Showing {(safePage - 1) * PAGE_SIZE + 1}–
                {Math.min(safePage * PAGE_SIZE, filtered.length)} of{" "}
                {filtered.length} results
              </p>

              <div className="flex items-center gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 w-8 p-0"
                  disabled={safePage === 1}
                  onClick={() => setCurrentPage((p) => p - 1)}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>

                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .filter((p) => {
                    if (totalPages <= 5) return true;

                    return (
                      Math.abs(p - safePage) <= 1 || p === 1 || p === totalPages
                    );
                  })
                  .reduce<(number | "…")[]>((acc, p, i, arr) => {
                    if (
                      i > 0 &&
                      typeof arr[i - 1] === "number" &&
                      (p as number) - (arr[i - 1] as number) > 1
                    ) {
                      acc.push("…");
                    }

                    acc.push(p);
                    return acc;
                  }, [])
                  .map((p, i) =>
                    p === "…" ? (
                      <span
                        key={`ellipsis-${i}`}
                        className="px-1 text-muted-foreground text-sm"
                      >
                        …
                      </span>
                    ) : (
                      <Button
                        key={p}
                        size="sm"
                        variant={p === safePage ? "default" : "outline"}
                        className="h-8 w-8 p-0 text-xs"
                        onClick={() => setCurrentPage(p as number)}
                      >
                        {p}
                      </Button>
                    ),
                  )}

                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 w-8 p-0"
                  disabled={safePage === totalPages}
                  onClick={() => setCurrentPage((p) => p + 1)}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
