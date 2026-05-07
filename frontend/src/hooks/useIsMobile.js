import { useState, useEffect } from 'react';

export function useIsMobile(breakpoint = 640) {
  const [isMobile, setIsMobile] = useState(
    () => window.innerWidth < breakpoint
  );

  useEffect(() => {
    const handler = () => setIsMobile(window.innerWidth < breakpoint);
    const observer = new ResizeObserver(handler);
    observer.observe(document.body);
    return () => observer.disconnect();
  }, [breakpoint]);

  return isMobile;
}