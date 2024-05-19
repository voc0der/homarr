"use client";

import { Button, Group, Stack } from "@mantine/core";

import type { WidgetKind } from "@homarr/definitions";
import { createModal } from "@homarr/modals";
import { useI18n } from "@homarr/translation/client";
import type { BoardItemIntegration } from "@homarr/validation";

import { widgetImports } from "..";
import { getInputForType } from "../_inputs";
import { FormProvider, useForm } from "../_inputs/form";
import type { OptionsBuilderResult } from "../options";
import type { IntegrationSelectOption } from "../widget-integration-select";
import { WidgetIntegrationSelect } from "../widget-integration-select";

export interface WidgetEditModalState {
  options: Record<string, unknown>;
  integrations: BoardItemIntegration[];
}

interface ModalProps<TSort extends WidgetKind> {
  kind: TSort;
  value: WidgetEditModalState;
  onSuccessfulEdit: (value: WidgetEditModalState) => void;
  integrationData: IntegrationSelectOption[];
  integrationSupport: boolean;
}

export const WidgetEditModal = createModal<ModalProps<WidgetKind>>(({ actions, innerProps }) => {
  const t = useI18n();
  const form = useForm({
    initialValues: innerProps.value,
  });

  const { definition } = widgetImports[innerProps.kind];

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        innerProps.onSuccessfulEdit(values);
        actions.closeModal();
      })}
    >
      <FormProvider form={form}>
        <Stack>
          {innerProps.integrationSupport && (
            <WidgetIntegrationSelect
              label={t("item.edit.field.integrations.label")}
              data={innerProps.integrationData}
              {...form.getInputProps("integrations")}
            />
          )}
          {Object.entries(definition.options).map(([key, value]: [string, OptionsBuilderResult[string]]) => {
            const Input = getInputForType(value.type);

            if (!Input || value.shouldHide?.(form.values.options as never)) {
              return null;
            }

            return <Input key={key} kind={innerProps.kind} property={key} options={value as never} />;
          })}
          <Group justify="right">
            <Button onClick={actions.closeModal} variant="subtle" color="gray">
              {t("common.action.cancel")}
            </Button>
            <Button type="submit" color="teal">
              {t("common.action.saveChanges")}
            </Button>
          </Group>
        </Stack>
      </FormProvider>
    </form>
  );
}).withOptions({
  keepMounted: true,
});
