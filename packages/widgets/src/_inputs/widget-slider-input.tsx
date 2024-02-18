"use client";

import { InputWrapper, Slider } from "@homarr/ui";

import type { CommonWidgetInputProps } from "./common";
import { useWidgetInputTranslation } from "./common";
import { useFormContext } from "./form";

export const WidgetSliderInput = ({
  property,
  kind,
  options,
}: CommonWidgetInputProps<"slider">) => {
  const t = useWidgetInputTranslation(kind, property);
  const form = useFormContext();

  return (
    <InputWrapper
      description={options.withDescription ? t("description") : undefined}
    >
      <Slider
        label={t("label")}
        min={options.validate.minValue ?? undefined}
        max={options.validate.maxValue ?? undefined}
        step={options.step}
        {...form.getInputProps(`options.${property}`)}
      />
    </InputWrapper>
  );
};