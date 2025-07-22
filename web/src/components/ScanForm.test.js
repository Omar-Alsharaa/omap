import { render } from '@testing-library/react';
import ScanForm from './ScanForm';
import { ScanProvider } from '../context/ScanContext';

test('renders scan form without crashing', () => {
  render(
    <ScanProvider>
      <ScanForm />
    </ScanProvider>
  );
  // Test passes if the component renders without throwing
});

test('scan form contains form elements', () => {
  const { container } = render(
    <ScanProvider>
      <ScanForm />
    </ScanProvider>
  );
  // Check that form elements are present
  expect(container.querySelector('form')).toBeTruthy();
});
