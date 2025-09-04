/**
 * Test utilities for NavbarSearch component
 */

import { NavbarSearch } from '../NavbarSearch';

// Mock test helper for unit testing
export const createMockAnalyze = () => {
  const mockAnalyze = jest.fn();
  return {
    mockAnalyze,
    getCallsWithQuery: () => mockAnalyze.mock.calls.map(call => call[0]),
    wasCalledWith: (expectedQuery: string) => {
      return mockAnalyze.mock.calls.some(call => call[0] === expectedQuery);
    },
    getLastCall: () => {
      const calls = mockAnalyze.mock.calls;
      return calls.length > 0 ? calls[calls.length - 1][0] : null;
    }
  };
};

// Integration test scenarios
export const testScenarios = {
  basicSubmit: {
    input: 'malware.example.com',
    expected: 'malware.example.com'
  },
  whitespaceNormalization: {
    input: '  example.com   with    spaces  ',
    expected: 'example.com with spaces'
  },
  emptyInput: {
    input: '   ',
    expected: null // Should not call onAnalyze
  },
  hashInput: {
    input: 'dd9136c086ff1946b50905ab51493e5d5059d61562cfdfa11ffd14bd180f10ea',
    expected: 'dd9136c086ff1946b50905ab51493e5d5059d61562cfdfa11ffd14bd180f10ea'
  },
  ipInput: {
    input: '192.168.1.100',
    expected: '192.168.1.100'
  }
};

// Usage example for testing:
/*
import { render, fireEvent, waitFor } from '@testing-library/react';
import { createMockAnalyze, testScenarios } from './NavbarSearch.test.utils';

test('NavbarSearch calls onAnalyze with normalized query', async () => {
  const { mockAnalyze, wasCalledWith } = createMockAnalyze();
  
  const { getByRole } = render(
    <NavbarSearch onAnalyze={mockAnalyze} />
  );
  
  const input = getByRole('textbox');
  const button = getByRole('button');
  
  fireEvent.change(input, { target: { value: testScenarios.whitespaceNormalization.input } });
  fireEvent.click(button);
  
  await waitFor(() => {
    expect(wasCalledWith(testScenarios.whitespaceNormalization.expected)).toBe(true);
  });
});
*/
