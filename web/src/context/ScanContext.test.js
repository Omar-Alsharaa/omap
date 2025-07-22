import { render } from '@testing-library/react';
import { ScanProvider } from './ScanContext';

test('ScanProvider renders children', () => {
  const TestComponent = () => <div>Test</div>;
  
  const { container } = render(
    <ScanProvider>
      <TestComponent />
    </ScanProvider>
  );
  
  expect(container.textContent).toContain('Test');
});
