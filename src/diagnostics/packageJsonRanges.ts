import { findNodeAtLocation, parseTree, type Node } from "jsonc-parser";

const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
] as const;

export function findDependencyOffsets(
  text: string,
  packageName: string
): { start: number; end: number } | undefined {
  const root = parseTree(text);
  if (!root) {
    return undefined;
  }

  for (const section of DEPENDENCY_SECTIONS) {
    const valueNode = findNodeAtLocation(root, [section, packageName]);
    const propertyNode = valueNode?.parent;
    if (propertyNode) {
      return { start: propertyNode.offset, end: propertyNode.offset + propertyNode.length };
    }
  }
  return undefined;
}

export function findDependencyNameAtOffset(text: string, offset: number): string | undefined {
  const root = parseTree(text);
  if (!root) {
    return undefined;
  }

  for (const section of DEPENDENCY_SECTIONS) {
    const sectionNode = findNodeAtLocation(root, [section]);
    if (!sectionNode?.children) {
      continue;
    }
    for (const propertyNode of sectionNode.children) {
      if (offset < propertyNode.offset || offset > propertyNode.offset + propertyNode.length) {
        continue;
      }
      const name = propertyKey(propertyNode);
      if (name) {
        return name;
      }
    }
  }
  return undefined;
}

function propertyKey(propertyNode: Node): string | undefined {
  const key = propertyNode.children?.[0];
  return typeof key?.value === "string" ? key.value : undefined;
}
