/** @type {import('ts-jest/dist/types').JestConfigWithTsJest} */

module.exports = {
  projects: ['<rootDir>/jest.unit.config.js', '<rootDir>/jest.e2e.config.js'],
  coveragePathIgnorePatterns: ['/node_modules/'],
  coverageThreshold: {
    global: {
      lines: 90,
    },
  },
}
