import React from "react";
import { Navigate } from "react-router-dom";

type Props = {
  isAuthenticated: boolean;
  children: React.ReactNode;
};

export function ProtectedRoute({ isAuthenticated, children }: Props) {
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
