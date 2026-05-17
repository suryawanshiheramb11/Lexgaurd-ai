import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';
import { describe, test, expect, vi } from 'vitest';
import axios from 'axios';

vi.mock('axios');

describe('App Component', () => {
  test('renders dashboard tabs correctly', () => {
    render(<App />);
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Document Library')).toBeInTheDocument();
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
    expect(screen.getByText('AI Advocate')).toBeInTheDocument();
  });

  test('switches to Prompt Shield tab', () => {
    render(<App />);
    const promptShieldBtn = screen.getByText('Threat Intelligence');
    fireEvent.click(promptShieldBtn);
    expect(screen.getByText('LLM Prompt Injection Shield')).toBeInTheDocument();
  });
  
  test('switches to AI Advocate tab', () => {
    render(<App />);
    const advocateBtn = screen.getByText('AI Advocate');
    fireEvent.click(advocateBtn);
    expect(screen.getByText('AI Legal Advocate')).toBeInTheDocument();
  });

  test('switches to Document Library tab', () => {
    render(<App />);
    const docLibraryBtn = screen.getByText('Document Library');
    fireEvent.click(docLibraryBtn);
    expect(screen.getByText('Contract Auditor & Legal Risk Analyzer')).toBeInTheDocument();
  });
});
