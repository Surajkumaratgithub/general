const formatUserData = (value) => {
  if (typeof value === "string") {
    return value.trim();
  }

  if (Array.isArray(value)) {
    return value.map(formatUserData);
  }

  if (typeof value === "object" && value !== null) {
    const result = {};
    for (const key in value) {
      result[key] = formatUserData(value[key]);
    }
    return result;
  }

  return value;
};
export default formatUserData;
