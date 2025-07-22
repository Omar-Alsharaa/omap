import { render } from '@testing-library/react';
import Dashboard from './Dashboard';
import { ScanProvider } from '../context/ScanContext';

test('renders dashboard without crashing', () => {
  render(
    <ScanProvider>
      <Dashboard />
    </ScanProvider>
  );
  // Test passes if the component renders without throwing
});
