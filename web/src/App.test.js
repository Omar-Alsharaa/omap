import { render } from '@testing-library/react';
import App from './App';

test('renders without crashing', () => {
  render(<App />);
  // Test passes if the component renders without throwing
});

test('contains OMAP text elements', () => {
  const { container } = render(<App />);
  // Test that the app contains expected text
  expect(container.textContent).toContain('OMAP');
});
