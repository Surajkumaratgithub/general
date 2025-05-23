import path from "path";
import { fileURLToPath } from "url";

export default function lazyLoadRoute(routePath) {
  let router = null;
  return async (req, res, next) => {
    try {
      if (!router) {
        const absolutePath = path.resolve(process.cwd(), routePath);
        const importedModule = await import(`file://${absolutePath}`);
        router = importedModule.default;
      }
      router(req, res, next);
    } catch (error) {
      console.error(`Error loading route ${routePath}:`, error);
      next(error);
    }
  };
}
