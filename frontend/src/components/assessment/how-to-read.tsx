import { HelpCircle } from "lucide-react";

import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Card } from "@/components/ui/card";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h4 className="text-xs font-medium uppercase tracking-[0.08em] text-muted-foreground">
        {title}
      </h4>
      <div className="space-y-2 text-sm leading-relaxed">{children}</div>
    </div>
  );
}

export function HowToRead() {
  return (
    <Card className="p-0">
      <Accordion type="single" collapsible defaultValue="how">
        <AccordionItem value="how" className="border-b-0">
          <AccordionTrigger className="px-6 py-4 hover:no-underline">
            <span className="flex items-center gap-2 text-sm font-medium">
              <HelpCircle className="size-4 text-muted-foreground" />
              How to read this page
            </span>
          </AccordionTrigger>

          <AccordionContent className="space-y-6 px-6 pb-6">
            <p className="text-sm leading-relaxed">
              This page is a report card from an exam given to the detector. It was
              asked 500 questions whose answers are already known: 250 URLs that really
              are phishing (&ldquo;did it catch them?&rdquo;) and 250 that really are
              safe (&ldquo;did it leave them alone?&rdquo;).
            </p>

            <p className="rounded-lg border bg-muted/40 px-3 py-2.5 text-sm leading-relaxed text-muted-foreground">
              A useful comparison is airport security: 250 smugglers and 250 ordinary
              passengers walk through the scanner. The results below describe how many
              of each were stopped.
            </p>

            <Section title="The four cards">
              <p>
                <span className="font-medium">Recall</span> &mdash; how many of the real
                scams were caught. <span className="font-medium">Precision</span> &mdash;
                when the alarm sounded, how often it was right.{" "}
                <span className="font-medium">F1</span> blends the two into one number so
                different settings can be compared at a glance.
              </p>
            </Section>

            <Section title="Scoring weight analysis">
              <p>
                The final score is a recipe: part rule engine, part classifier. This
                table re-marks the same 500 answers using different recipes, so you can
                see whether a missed attack was invisible to the detector or simply
                averaged away by the scoring formula. The row marked{" "}
                <span className="font-mono text-xs">current</span> is what the scanner
                actually uses today.
              </p>
            </Section>

            <Section title="Confusion matrix">
              <p>
                The same results expressed as four counts: scams caught, scams missed,
                safe sites correctly cleared, and safe sites wrongly flagged. The four
                numbers add up to the full test set.
              </p>
            </Section>

            <Section title="Detection gaps by attack type">
              <p>
                The phishing URLs sorted into categories, showing the catch rate for
                each. A long green bar is an attack type the detector handles well; a
                short bar is a blind spot.
              </p>
            </Section>

            <Section title="The two lists at the bottom">
              <p>
                The actual mistakes, so each one can be inspected. Missed URLs show why
                they slipped through &mdash; most have no visible warning signs in the
                address at all. Wrongly flagged URLs are usually genuine sign-in pages,
                which contain the same words (&ldquo;login&rdquo;,
                &ldquo;account&rdquo;, &ldquo;secure&rdquo;) that phishing sites use
                precisely because they are imitating them.
              </p>
            </Section>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </Card>
  );
}
