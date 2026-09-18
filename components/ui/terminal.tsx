'use client';

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

// Magic UI Terminal chrome — https://magicui.design/docs/components/terminal.
// Ported without the lib's motion-based <TypingAnimation>/<AnimatedSpan> helpers:
// this shell hosts a live xterm VT stream (and a static command <pre>), not
// scripted lines, so that animation engine — and its `motion` dependency —
// would render nothing here. Same window chrome, cohesive dark terminal body.
export function Terminal({
  children,
  title,
  className,
}: {
  children: ReactNode;
  title?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'z-0 w-full max-w-full overflow-hidden rounded-xl border border-border bg-neutral-50 text-neutral-800 shadow-sm dark:bg-[#0a0a0a] dark:text-neutral-100',
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b border-border bg-black/[0.02] px-4 py-3 dark:border-white/10 dark:bg-white/[0.03]">
        <div className="flex flex-row gap-x-2">
          <span className="size-3 rounded-full bg-red-500" />
          <span className="size-3 rounded-full bg-yellow-500" />
          <span className="size-3 rounded-full bg-green-500" />
        </div>
        {title != null && (
          <span className="ml-1 truncate font-mono text-xs text-neutral-500 dark:text-neutral-400">{title}</span>
        )}
      </div>
      <div className="overflow-x-auto p-3">{children}</div>
    </div>
  );
}
