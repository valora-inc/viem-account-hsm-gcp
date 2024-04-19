/** @type {import('ts-jest/dist/types').JestConfigWithTsJest} */

module.exports = {
  displayName: 'unit',
  testMatch: [
    '**/__tests__/**/unit/**/*.[tj]s?(x)',
    '**/?(*.)+(test|unit).[tj]s?(x)',
  ],
  testPathIgnorePatterns: ['dist'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  // Allow absolute imports from the tsconfig baseUrl
  moduleDirectories: ['node_modules', '<rootDir>'],
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
  },
  setupFilesAfterEnv: ['<rootDir>/jest.unit.setup.js'],
}
