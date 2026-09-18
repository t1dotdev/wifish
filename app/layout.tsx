import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { Inter, Press_Start_2P } from "next/font/google";
import { cn } from "@/lib/utils";

const inter = Inter({subsets:['latin'],variable:'--font-sans'});
const pixel = Press_Start_2P({subsets:['latin'],weight:'400',variable:'--font-pixel'});

export const metadata: Metadata = {
  title: 'wifish · WPA panel',
  description: 'WPA/WPA2 handshake file panel',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={cn("font-sans", inter.variable, pixel.variable)} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{var t=localStorage.getItem('theme');if(t==='dark'||(!t&&matchMedia('(prefers-color-scheme:dark)').matches))document.documentElement.classList.add('dark')}catch(e){}`,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
