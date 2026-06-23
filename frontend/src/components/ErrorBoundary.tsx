import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Frontend error boundary:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="m-8 rounded-lg border border-red-500/40 bg-red-500/10 p-6 text-red-200">
          Ocurrio un error inesperado en el dashboard.
        </div>
      );
    }

    return this.props.children;
  }
}

