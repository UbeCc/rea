import { POSITIONAL_SELECTOR_OPTIONS } from "./coreBinaryCommands.js";

/**
 * One argv token spelling an Objective-C instance method, such as
 * `-[QuickOpenCommands buildPredicateQueryFrom:]`. Its brackets and space
 * cannot occur in a flag, so the token is unambiguously a selector value.
 */
const OBJC_INSTANCE_METHOD_TOKEN = /^-\[[^\s[\]]+ [^\s[\]]+\]$/u;

/**
 * Bind a positional Objective-C instance method selector to the command's
 * named selector option before Incur tokenizes it as an unknown flag. Every
 * other token, including explicit named selectors, is preserved unchanged.
 */
export const normalizeCliPositionalSelectors = (
  arguments_: readonly string[],
): string[] => {
  const command = arguments_.find((argument) =>
    Object.hasOwn(POSITIONAL_SELECTOR_OPTIONS, argument),
  );
  const option =
    command === undefined ? undefined : POSITIONAL_SELECTOR_OPTIONS[command];
  if (option === undefined) return [...arguments_];
  const named = `--${option}`;
  // A spaced `--procedure -[...]` already supplies the value, and a second
  // named selector would silently replace the first one.
  if (
    arguments_.some(
      (argument) => argument === named || argument.startsWith(`${named}=`),
    )
  )
    return [...arguments_];
  let bound = false;
  return arguments_.map((argument) => {
    if (bound || !OBJC_INSTANCE_METHOD_TOKEN.test(argument)) return argument;
    bound = true;
    return `${named}=${argument}`;
  });
};
