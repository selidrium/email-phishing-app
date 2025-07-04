/**
 * Utility function to extract error messages from API responses
 * Handles different error response formats from FastAPI
 */
export const extractErrorMessage = (err, defaultMessage = "An error occurred") => {
  if (!err.response?.data) {
    return defaultMessage;
  }

  const data = err.response.data;

  // Handle single error message
  if (data.detail) {
    return data.detail;
  }

  // Handle validation errors array (FastAPI 422 responses)
  if (Array.isArray(data)) {
    return data.map(error => error.msg).join(', ');
  }

  // Handle other error object formats
  if (typeof data === 'object') {
    return Object.values(data).join(', ');
  }

  // Handle string errors
  if (typeof data === 'string') {
    return data;
  }

  return defaultMessage;
}; 